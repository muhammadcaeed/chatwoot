class Rack::Attack
  ### Configure Cache ###

  # If you don't want to use Rails.cache (Rack::Attack's default), then
  # configure it here.
  #
  # Note: The store is only used for throttling (not blocklisting and
  # safelisting). It must implement .increment and .write like
  # ActiveSupport::Cache::Store

  # Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new

  # https://github.com/rack/rack-attack/issues/102
  # Rails 7.1 automatically adds its own ConnectionPool around RedisCacheStore.
  # Because `$velma` is *already* a ConnectionPool, double-wrapping causes
  # Redis calls like `get` to hit the outer wrapper and explode.
  # `pool: false` tells Rails to skip its internal pool and use ours directly.
  # TODO: We can use build in connection pool in future upgrade
  Rack::Attack.cache.store = ActiveSupport::Cache::RedisCacheStore.new(redis: $velma, pool: false)

  class Request < ::Rack::Request
    # You may need to specify a method to fetch the correct remote IP address
    # if the web server is behind a load balancer.
    def remote_ip
      @remote_ip ||= (env['action_dispatch.remote_ip'] || ip).to_s
    end

    def allowed_ip?
      default_allowed_ips = ['127.0.0.1', '::1']
      env_allowed_ips = ENV.fetch('RACK_ATTACK_ALLOWED_IPS', '').split(',').map(&:strip)
      (default_allowed_ips + env_allowed_ips).include?(remote_ip)
    end

    # Rails would allow requests to paths with extensions, so lets compare against the path with extension stripped
    # example /auth & /auth.json would both work
    def path_without_extensions
      path[/^[^.]+/]
    end
  end

  ### Safelist IPs from Environment Variable ###
  #
  # This block ensures requests from any IP present in RACK_ATTACK_ALLOWED_IPS
  # will bypass Rack::Attack’s throttling rules.
  #
  # Example: RACK_ATTACK_ALLOWED_IPS="127.0.0.1,::1,192.168.0.10"

  Rack::Attack.safelist('trusted IPs', &:allowed_ip?)

  # Safelist health check endpoint so it never touches Redis for throttle tracking.
  # This keeps /health fully dependency-free for ALB liveness checks.
  Rack::Attack.safelist('health check') do |req|
    req.path == '/health'
  end

  ### Throttle Spammy Clients ###

  # If any single client IP is making tons of requests, then they're
  # probably malicious or a poorly-configured scraper. Either way, they
  # don't deserve to hog all of the app server's CPU. Cut them off!
  #
  # Note: If you're serving assets through rack, those requests may be
  # counted by rack-attack and this throttle may be activated too
  # quickly. If so, enable the condition to exclude them from tracking.

  # Throttle all requests by IP (60rpm)
  #
  # Key: "rack::attack:#{Time.now.to_i/:period}:req/ip:#{req.ip}"

  throttle('req/ip', limit: ENV.fetch('RACK_ATTACK_LIMIT', '3000').to_i, period: 1.minute, &:ip)

  ###-----------------------------------------------###
  ###-----Authentication Related Throttling---------###
  ###-----------------------------------------------###

  ### Prevent Brute-Force Super Admin Login Attacks ###
  throttle('super_admin_login/ip', limit: 5, period: 5.minutes) do |req|
    req.ip if req.path_without_extensions == '/super_admin/sign_in' && req.post?
  end

  throttle('super_admin_login/email', limit: 5, period: 15.minutes) do |req|
    if req.path_without_extensions == '/super_admin/sign_in' && req.post?
      # NOTE: This line used to throw ArgumentError /rails/action_mailbox/sendgrid/inbound_emails : invalid byte sequence in UTF-8
      # Hence placed in the if block
      # ref: https://github.com/rack/rack-attack/issues/399
      email = req.params['email'].presence || ActionDispatch::Request.new(req.env).params['email'].presence
      email.to_s.downcase.gsub(/\s+/, '')
    end
  end

  # ### Prevent Brute-Force Login Attacks ###
  # Exclude MFA verification attempts from regular login throttling
  throttle('login/ip', limit: 5, period: 5.minutes) do |req|
    if req.path_without_extensions == '/auth/sign_in' && req.post? && req.params['mfa_token'].blank?
      # Skip if this is an MFA verification request
      req.ip
    end
  end

  throttle('login/email', limit: 10, period: 15.minutes) do |req|
    # Skip if this is an MFA verification request
    if req.path_without_extensions == '/auth/sign_in' && req.post? && req.params['mfa_token'].blank?
      # ref: https://github.com/rack/rack-attack/issues/399
      # NOTE: This line used to throw ArgumentError /rails/action_mailbox/sendgrid/inbound_emails : invalid byte sequence in UTF-8
      # Hence placed in the if block
      email = req.params['email'].presence || ActionDispatch::Request.new(req.env).params['email'].presence
      email.to_s.downcase.gsub(/\s+/, '')
    end
  end

  ## Reset password throttling
  throttle('reset_password/ip', limit: 5, period: 30.minutes) do |req|
    req.ip if req.path_without_extensions == '/auth/password' && req.post?
  end

  throttle('reset_password/email', limit: 5, period: 1.hour) do |req|
    if req.path_without_extensions == '/auth/password' && req.post?
      email = req.params['email'].presence || ActionDispatch::Request.new(req.env).params['email'].presence
      email.to_s.downcase.gsub(/\s+/, '')
    end
  end

  ## Resend confirmation throttling (unauthenticated)
  throttle('resend_confirmation/ip', limit: 5, period: 30.minutes) do |req|
    req.ip if req.path_without_extensions == '/resend_confirmation' && req.post?
  end

  throttle('resend_confirmation/email', limit: 5, period: 1.hour) do |req|
    if req.path_without_extensions == '/resend_confirmation' && req.post?
      email = req.params['email'].presence || ActionDispatch::Request.new(req.env).params['email'].presence
      email.to_s.downcase.gsub(/\s+/, '')
    end
  end

  ## Resend confirmation throttling (authenticated)
  throttle('resend_confirmation_auth/ip', limit: 5, period: 30.minutes) do |req|
    req.ip if req.path_without_extensions == '/api/v1/profile/resend_confirmation' && req.post?
  end

  ## MFA throttling - prevent brute force attacks
  throttle('mfa_verification/ip', limit: 5, period: 1.minute) do |req|
    if req.path_without_extensions == '/api/v1/profile/mfa'
      req.ip if req.delete? # Throttle disable attempts
    elsif req.path_without_extensions.match?(%r{/api/v1/profile/mfa/(verify|backup_codes)})
      req.ip if req.post? # Throttle verify and backup_codes attempts
    end
  end

  # Separate rate limiting for MFA verification attempts
  throttle('mfa_login/ip', limit: 10, period: 1.minute) do |req|
    req.ip if req.path_without_extensions == '/auth/sign_in' && req.post? && req.params['mfa_token'].present?
  end

  throttle('mfa_login/token', limit: 10, period: 1.minute) do |req|
    if req.path_without_extensions == '/auth/sign_in' && req.post?
      # Track by MFA token to prevent brute force on a specific token
      mfa_token = req.params['mfa_token'].presence
      (mfa_token.presence)
    end
  end

  ## Prevent Brute-Force Signup Attacks ###
  throttle('accounts/ip', limit: 5, period: 30.minutes) do |req|
    req.ip if req.path_without_extensions == '/api/v1/accounts' && req.post?
  end

  ##-----------------------------------------------##

  ###-----------------------------------------------###
  ###-----------Widget API Throttling---------------###
  ###-----------------------------------------------###

  # Rack attack on widget APIs can be disabled by setting ENABLE_RACK_ATTACK_WIDGET_API to false
  # For clients using the widgets in specific conditions like inside and iframe
  # TODO: Deprecate this feature in future after finding a better solution
  if ActiveModel::Type::Boolean.new.cast(ENV.fetch('ENABLE_RACK_ATTACK_WIDGET_API', true))
    ## Prevent Conversation Bombing on Widget APIs ###
    throttle('api/v1/widget/conversations', limit: ENV.fetch('RATE_LIMIT_WIDGET_CONVERSATIONS', '3').to_i, period: 1.hour) do |req|
      req.ip if req.path_without_extensions == '/api/v1/widget/conversations' && req.post?
    end

    ## Prevent Contact update Bombing in Widget API ###
    throttle('api/v1/widget/contacts', limit: 60, period: 1.hour) do |req|
      req.ip if req.path_without_extensions == '/api/v1/widget/contacts' && (req.patch? || req.put?)
    end

    ## Prevent Conversation Bombing through multiple sessions
    throttle('widget?website_token={website_token}&cw_conversation={x-auth-token}',
             limit: ENV.fetch('RATE_LIMIT_WIDGET_PAGE_LOADS', '50').to_i, period: 1.hour) do |req|
      req.ip if req.path_without_extensions == '/widget' && ActionDispatch::Request.new(req.env).params['cw_conversation'].blank?
    end
  end

  ##-----------------------------------------------##

  ###-----------------------------------------------###
  ###----------Application API Throttling-----------###
  ###-----------------------------------------------###

  ## Prevent Abuse of Converstion Transcript APIs ###
  throttle('/api/v1/accounts/:account_id/conversations/:conversation_id/transcript',
           limit: ENV.fetch('RATE_LIMIT_CONVERSATION_TRANSCRIPT', '1000').to_i, period: 1.hour) do |req|
    match_data = %r{/api/v1/accounts/(?<account_id>\d+)/conversations/(?<conversation_id>\d+)/transcript}.match(req.path)
    match_data[:account_id] if match_data.present?
  end

  ## Prevent Abuse of attachment upload APIs ##
  throttle('/api/v1/accounts/:account_id/upload', limit: 60, period: 1.hour) do |req|
    match_data = %r{/api/v1/accounts/(?<account_id>\d+)/upload}.match(req.path)
    match_data[:account_id] if match_data.present?
  end

  ## Prevent abuse of contact search api
  throttle('/api/v1/accounts/:account_id/contacts/search', limit: ENV.fetch('RATE_LIMIT_CONTACT_SEARCH', '100').to_i, period: 1.minute) do |req|
    match_data = %r{/api/v1/accounts/(?<account_id>\d+)/contacts/search}.match(req.path)
    match_data[:account_id] if match_data.present?
  end

  # Throttle by individual user (based on uid)
  throttle('/api/v2/accounts/:account_id/reports/user', limit: ENV.fetch('RATE_LIMIT_REPORTS_API_USER_LEVEL', '100').to_i, period: 1.minute) do |req|
    match_data = %r{/api/v2/accounts/(?<account_id>\d+)/reports}.match(req.path)
    # Extract user identification (uid for web, api_access_token for API requests)
    user_uid = req.get_header('HTTP_UID')
    api_access_token = req.get_header('HTTP_API_ACCESS_TOKEN') || req.get_header('api_access_token')

    # Use uid if present, otherwise fallback to api_access_token for tracking
    user_identifier = user_uid.presence || api_access_token.presence

    "#{user_identifier}:#{match_data[:account_id]}" if match_data.present? && user_identifier.present?
  end

  ## Prevent abuse of reports api at account level
  throttle('/api/v2/accounts/:account_id/reports', limit: ENV.fetch('RATE_LIMIT_REPORTS_API_ACCOUNT_LEVEL', '1000').to_i, period: 1.minute) do |req|
    match_data = %r{/api/v2/accounts/(?<account_id>\d+)/reports}.match(req.path)
    match_data[:account_id] if match_data.present?
  end

  ## Prevent increased use of conversations meta API per user
  throttle('/api/v1/accounts/:account_id/conversations/meta/user',
           limit: ENV.fetch('RATE_LIMIT_CONVERSATIONS_META', '30').to_i, period: 1.minute) do |req|
    match_data = %r{/api/v1/accounts/(?<account_id>\d+)/conversations/meta}.match(req.path)
    next unless match_data.present? && req.get?

    user_uid = req.get_header('HTTP_UID')
    api_access_token = req.get_header('HTTP_API_ACCESS_TOKEN') || req.get_header('api_access_token')
    user_identifier = user_uid.presence || api_access_token.presence

    "#{user_identifier}:#{match_data[:account_id]}" if user_identifier.present?
  end

  ## ----------------------------------------------- ##

  ###-----------------------------------------------###
  ###------TEMP DIAGNOSTIC - REMOVE AFTER USE-------###
  ###-----------------------------------------------###
  # Counts and reports every request without ever blocking one, so we can see
  # what `req.ip` actually resolves to behind Railway's edge + the Caddy proxy.
  # Paired with the 'track.rack_attack' subscriber at the bottom of this file.
  track('diag/every-request', limit: 0, period: 60, &:ip)
end

# Log blocked events
ActiveSupport::Notifications.subscribe('throttle.rack_attack') do |_name, _start, _finish, _request_id, payload|
  req = payload[:request]

  user_uid = req.get_header('HTTP_UID')
  api_access_token = req.get_header('HTTP_API_ACCESS_TOKEN') || req.get_header('api_access_token')

  # Mask the token if present
  masked_api_token = api_access_token.present? ? "#{api_access_token[0..4]}...[REDACTED]" : nil

  # Use uid if present, otherwise fallback to masked api_access_token for tracking
  user_identifier = user_uid.presence || masked_api_token.presence || 'unknown_user'

  # Extract account ID if present
  account_match = %r{/accounts/(?<account_id>\d+)}.match(req.path)
  account_id = account_match ? account_match[:account_id] : 'unknown_account'

  Rails.logger.warn(
    "[Rack::Attack][Blocked] remote_ip: \"#{req.remote_ip}\", " \
    "path: \"#{req.path}\", " \
    "user_identifier: \"#{user_identifier}\", " \
    "account_id: \"#{account_id}\", " \
    "method: \"#{req.request_method}\", " \
    "user_agent: \"#{req.user_agent}\""
  )
end

###-----------------------------------------------###
###------Throttled Response (widget page load)-----###
###-----------------------------------------------###
# rack-attack's stock 429 body is the plain string "Retry later", which renders
# as a bare black box inside the customer's chat iframe. Confirmed live on
# 24 Aug 2026. Give a throttled /widget page load a branded page instead.
#
# Scoped to the /widget page by path. Every other throttle keeps the plain-text
# body it has always had, because the widget's XHR callers and the API expect a
# body they can parse, not a page. `req.path` is used rather than the file's own
# `path_without_extensions` helper on purpose: upstream renamed that method in
# 2663a8495, and a NoMethodError here would turn EVERY throttled request into a
# 500, including API ones.
#
# Note this also adds a `retry-after` header to every throttled response. The
# stock responder omits it (throttled_response_retry_after_header defaults to
# false), so this is a real change to API responses, and a standards-correct one.
Rack::Attack::WIDGET_THROTTLED_HTML = <<~HTML.freeze
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="robots" content="noindex">
    <title>Chat is taking a short break</title>
    <style>
      *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
      body {
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 1.5rem;
        background: #F6F5F2;
        color: #1B1B1B;
        font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
        line-height: 1.55;
        -webkit-font-smoothing: antialiased;
      }
      .card {
        width: 100%;
        max-width: 24rem;
        background: #FFFFFF;
        border: 1px solid #E4E1DA;
        border-radius: 6px;
        padding: 2rem 1.75rem 1.75rem;
      }
      .mark {
        display: block;
        font-size: 0.6875rem;
        letter-spacing: 0.18em;
        text-transform: uppercase;
        font-weight: 700;
        color: #8C6E33;
        margin-bottom: 1.125rem;
      }
      h1 { font-size: 1.25rem; line-height: 1.25; margin-bottom: 0.75rem; }
      p { font-size: 0.9375rem; color: #55555A; margin-bottom: 0.75rem; }
      p.lead { color: #1B1B1B; }
      .when { font-weight: 700; color: #1B1B1B; }
      .help {
        margin: 1.25rem 0 0;
        padding-top: 1rem;
        border-top: 1px solid #E4E1DA;
        font-size: 0.8125rem;
      }
      .help a { color: #8C6E33; font-weight: 700; text-decoration: none; overflow-wrap: anywhere; }
      .help a:hover { text-decoration: underline; }
      @media (prefers-color-scheme: dark) {
        body { background: #131315; color: #ECEAE6; }
        .card { background: #1C1C1F; border-color: #33322E; }
        .mark { color: #C9A75C; }
        p { color: #A9A69F; }
        p.lead, .when { color: #ECEAE6; }
        .help { border-top-color: #33322E; }
        .help a { color: #C9A75C; }
      }
    </style>
  </head>
  <body>
    <div class="card">
      <span class="mark">Newman Bands</span>
      <h1>Chat is taking a short break</h1>
      <p class="lead">The chat has been opened a lot from this connection in the last little while, so it's paused for a moment. Nothing is wrong with your order or your account.</p>
      <p>Please try again <span class="when">{{WAIT}}</span>.</p>
      <p class="help">Need help sooner? Email us and include your order number.<br>
        <a href="mailto:support@newmanbands.com">support@newmanbands.com</a>
      </p>
    </div>
  </body>
  </html>
HTML

Rack::Attack.throttled_responder = lambda do |req|
  # match_data is always populated before the responder runs (rack-attack 6.7.0,
  # lib/rack/attack/throttle.rb). Nil-safe anyway: this lambda is GLOBAL, so an
  # exception here would turn every throttled request into a 500, API included.
  #
  # The window is FIXED, not sliding, so this is the time left in the current
  # window rather than a full period. For the /widget throttle (1 hour) that
  # reads as anything from seconds to 59 minutes, which is honest.
  match_data = req.env['rack.attack.match_data'] || {}
  period = match_data[:period].to_i
  retry_after = period.positive? ? period - (match_data[:epoch_time].to_i % period) : 60
  headers = { 'content-type' => 'text/plain', 'retry-after' => retry_after.to_s }

  if req.path == '/widget'
    minutes = (retry_after / 60.0).ceil
    wait_text = minutes > 1 ? "in about #{minutes} minutes" : 'in less than a minute'
    body = Rack::Attack::WIDGET_THROTTLED_HTML.sub('{{WAIT}}', wait_text)

    [429, headers.merge('content-type' => 'text/html; charset=utf-8'), [body]]
  else
    [429, headers, ["Retry later\n"]]
  end
end

# TEMP DIAGNOSTIC - REMOVE AFTER USE. Logs the discriminator the throttles key on.
ActiveSupport::Notifications.subscribe('track.rack_attack') do |_name, _start, _finish, _request_id, payload|
  req = payload[:request]

  Rails.logger.warn(
    "[RA-DIAG] req.ip: \"#{req.ip}\", " \
    "remote_ip: \"#{req.remote_ip}\", " \
    "REMOTE_ADDR: \"#{req.get_header('REMOTE_ADDR')}\", " \
    "XFF: \"#{req.get_header('HTTP_X_FORWARDED_FOR')}\", " \
    "path: \"#{req.path}\""
  )
end

Rack::Attack.enabled = Rails.env.production? ? ActiveModel::Type::Boolean.new.cast(ENV.fetch('ENABLE_RACK_ATTACK', true)) : false
