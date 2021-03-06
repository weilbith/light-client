<template>
  <div>
    <v-row align="start" justify="center" no-gutters class="token-information">
      <v-col cols="2">
        <div class="token-information__label">
          {{ $t('token-information.title') }}
        </div>
      </v-col>
      <v-col cols="8">
        <div class="token-information__description">
          {{
            $t('token-information.description', {
              symbol: token.symbol,
              name: token.name,
            })
          }}
        </div>
        <div class="token-information__address">
          <address-display :address="token.address" />
        </div>
      </v-col>
    </v-row>
    <v-row align="start" justify="center" no-gutters class="token-information">
      <v-col cols="2">
        <div class="token-information__label">
          {{ $t('token-information.balance') }}
        </div>
      </v-col>
      <v-col cols="8">
        <div class="token-information__description">
          <span class="token-information__balance">
            {{ (token.balance || 0) | displayFormat(token.decimals) }}
          </span>
          <v-tooltip v-if="!mainnet" bottom>
            <template #activator="{ on }">
              <v-btn
                text
                icon
                small
                class="token-information__mint"
                @click="showMintDialog = true"
                v-on="on"
              >
                <v-icon color="primary">play_for_work</v-icon>
              </v-btn>
            </template>
            <span>
              {{ $t('mint-dialog.title', { symbol: token.symbol || '' }) }}
            </span>
          </v-tooltip>
        </div>
      </v-col>
    </v-row>
    <mint-dialog
      :token="token"
      :visible="showMintDialog"
      @cancel="showMintDialog = false"
      @done="tokenMinted()"
    />
  </div>
</template>
<script lang="ts">
import { Component, Prop, Vue } from 'vue-property-decorator';
import { Token } from '@/model/types';
import AddressDisplay from '@/components/AddressDisplay.vue';
import MintDialog from '@/components/dialogs/MintDialog.vue';
import { mapGetters } from 'vuex';

@Component({
  components: { AddressDisplay, MintDialog },
  computed: {
    ...mapGetters(['mainnet']),
  },
})
export default class TokenInformation extends Vue {
  @Prop()
  token!: Token;

  getToken!: (address: string) => Token;
  mainnet!: boolean;
  showMintDialog: boolean = false;

  async tokenMinted() {
    this.showMintDialog = false;

    // Update token information
    await this.$raiden.fetchTokenData([this.token.address]);
  }
}
</script>
<style scoped lang="scss">
@import '@/scss/fonts';
@import '@/scss/mixins';

.token-information {
  height: auto;
  margin-top: 25px;

  &__label {
    color: #ffffff;
    font-family: $main-font;
    font-size: 16px;
    font-weight: bold;
    text-transform: uppercase;
    line-height: 28px;
  }

  &__description {
    display: flex;
    align-items: flex-start;
    color: #ffffff;
    font-family: $main-font;
    font-size: 16px;
    overflow-x: visible;
    text-overflow: ellipsis;
    line-height: 28px;
    @include respond-to(handhelds) {
      margin-left: 20px;
      width: 100%;
    }
  }

  &__address {
    @include respond-to(handhelds) {
      margin-left: 20px;
    }
  }

  &__balance {
    margin-right: 10px;
  }
}
</style>
