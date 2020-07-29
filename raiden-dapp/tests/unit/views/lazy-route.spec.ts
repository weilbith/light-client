import Vue from 'vue';
import Vuetify from 'vuetify';
import { mount, Wrapper } from '@vue/test-utils';
import store from '@/store';
import { $identicon } from '../utils/mocks';
import { connectAccount } from '../utils/store-utils';
import LazyRoute from '@/views/LazyRoute.vue';

Vue.use(Vuetify);

describe('LazyRoute.vue', () => {
  let wrapper: Wrapper<LazyRoute>;
  let vuetify: typeof Vuetify;

  beforeEach(() => {
    vuetify = new Vuetify();
    wrapper = mount(LazyRoute, {
      vuetify,
      store,
      stubs: ['home'],
      slots: {
        default: '<div class="actual-route"/>',
      },
      mocks: {
        $identicon: $identicon(),
        $t: (msg: string) => msg,
      },
    });
  });

  test('disconnected displays home', async () => {
    expect(wrapper.find('home-stub').exists()).toBe(true);
  });

  test('connected displays actual route', async () => {
    connectAccount();
    await wrapper.vm.$nextTick();
    expect(wrapper.find('home-stub').exists()).toBe(false);
    expect(wrapper.find('.actual-route').exists()).toBe(true);
  });
});
