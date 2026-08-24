<script>
import { BUS_EVENTS } from 'shared/constants/busEvents';
import { emitter } from 'shared/helpers/mitt';

export default {
  data() {
    return {
      showBannerMessage: false,
      bannerMessage: '',
      bannerType: 'error',
    };
  },
  mounted() {
    // `duration` defaults to the original 3000, so every existing caller keeps
    // its exact behaviour. It exists because a message carrying an email
    // address needs longer than three seconds to read and copy.
    emitter.on(
      BUS_EVENTS.SHOW_ALERT,
      ({ message, type = 'error', duration = 3000 }) => {
        this.bannerMessage = message;
        this.bannerType = type;
        this.showBannerMessage = true;
        setTimeout(() => {
          this.showBannerMessage = false;
        }, duration);
      }
    );
  },
};
</script>

<!-- eslint-disable-next-line vue/no-root-v-if -->
<template>
  <div v-if="showBannerMessage" :class="`banner ${bannerType}`">
    <span>
      {{ bannerMessage }}
    </span>
  </div>
</template>

<style scoped lang="scss">
.banner {
  @apply text-white text-sm font-semibold p-3 text-center;

  &.success {
    @apply bg-n-teal-9;
  }

  &.error {
    @apply bg-n-ruby-9;
  }
}
</style>
