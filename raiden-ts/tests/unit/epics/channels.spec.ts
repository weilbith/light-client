/* eslint-disable @typescript-eslint/camelcase */
import { raidenEpicDeps, makeLog, makeRaidens, makeHash, waitBlock } from '../mocks';
import {
  epicFixtures,
  token,
  tokenNetwork,
  id,
  openBlock,
  closeBlock,
  settleBlock,
  settleTimeout,
  txHash,
  ensureChannelIsClosed,
  ensureChannelIsOpen,
  ensureTokenIsMonitored,
  deposit,
  confirmationBlocks,
  ensureChannelIsDeposited,
} from '../fixtures';

import { of } from 'rxjs';
import { first, pluck } from 'rxjs/operators';
import { ContractTransaction } from 'ethers/contract';
import { bigNumberify, BigNumber } from 'ethers/utils';
import { Zero, HashZero, One } from 'ethers/constants';
import { defaultAbiCoder } from 'ethers/utils/abi-coder';

import { UInt, Int } from 'raiden-ts/utils/types';
import { RaidenAction } from 'raiden-ts/actions';
import { RaidenState } from 'raiden-ts/state';
import {
  newBlock,
  tokenMonitored,
  channelMonitor,
  channelOpen,
  channelDeposit,
  channelClose,
  channelSettleable,
  channelSettle,
  channelWithdrawn,
} from 'raiden-ts/channels/actions';
import {
  channelCloseEpic,
  channelSettleEpic,
  channelUpdateEpic,
  channelUnlockEpic,
} from 'raiden-ts/channels/epics';
import { raidenReducer } from 'raiden-ts/reducer';
import {
  makeSecret,
  getSecrethash,
  makePaymentId,
  makeMessageId,
  getLocksroot,
} from 'raiden-ts/transfers/utils';
import { Direction } from 'raiden-ts/transfers/state';
import { MessageType } from 'raiden-ts/messages/types';
import { signMessage } from 'raiden-ts/messages/utils';
import { transferSigned, transferUnlock } from 'raiden-ts/transfers/actions';
import { channelKey, channelUniqueKey } from 'raiden-ts/channels/utils';
import { ChannelState } from 'raiden-ts/channels';
import { TokenNetwork } from 'raiden-ts/contracts/TokenNetwork';
import { Filter } from 'ethers/providers';

describe('channels epic', () => {
  const depsMock = raidenEpicDeps();
  const { tokenNetworkContract, partner, isFirstParticipant, state } = epicFixtures(depsMock);

  beforeAll(() => jest.useRealTimers());

  test.only('channelSettleableEpic', async () => {
    expect.assertions(3);

    const [raiden, partner] = await makeRaidens(2);
    await ensureChannelIsClosed([raiden, partner]);

    const key = channelKey({ tokenNetwork, partner });

    await waitBlock(closeBlock + settleTimeout - 1);
    expect(raiden.store.getState().channels[key].state).toBe(ChannelState.closed);

    await waitBlock(closeBlock + settleTimeout + 7);
    expect(raiden.store.getState().channels[key].state).toBe(ChannelState.settleable);
    expect(raiden.output).toContainEqual(
      channelSettleable(
        { settleableBlock: closeBlock + settleTimeout + 7 },
        { tokenNetwork, partner: partner.address },
      ),
    );
  });

  describe.only('channelOpenEpic', () => {
    test('fails if channel exists', async () => {
      expect.assertions(2);

      const [raiden, partner] = await makeRaidens(2);
      await ensureChannelIsOpen([raiden, partner]);

      raiden.store.dispatch(
        channelOpen.request({ settleTimeout }, { tokenNetwork, partner: partner.address }),
      );
      expect(raiden.store.getState().channels[channelKey({ tokenNetwork, partner })].state).toBe(
        ChannelState.open,
      );
      expect(raiden.output).toContainEqual(
        channelOpen.failure(expect.any(Error), { tokenNetwork, partner: partner.address }),
      );
    });

    test('tx fails', async () => {
      expect.assertions(2);

      const [raiden, partner] = await makeRaidens(2);
      await ensureTokenIsMonitored(raiden);

      const tokenNetworkContract = raiden.deps.getTokenNetworkContract(tokenNetwork);
      const tx: ContractTransaction = {
        hash: makeHash(),
        confirmations: 1,
        nonce: 1,
        gasLimit: bigNumberify(1e6),
        gasPrice: bigNumberify(2e10),
        value: Zero,
        data: '0x',
        chainId: raiden.deps.network.chainId,
        from: raiden.address,
        wait: jest.fn().mockResolvedValue({ byzantium: true, status: 0 }),
      };
      tokenNetworkContract.functions.openChannel.mockResolvedValue(tx);

      await waitBlock(openBlock);
      raiden.store.dispatch(
        channelOpen.request({ settleTimeout }, { tokenNetwork, partner: partner.address }),
      );
      await waitBlock();
      expect(tokenNetworkContract.functions.openChannel).toHaveBeenCalled();
      expect(raiden.output).toContainEqual(
        channelOpen.failure(expect.any(Error), { tokenNetwork, partner: partner.address }),
      );
    });

    test('success', async () => {
      expect.assertions(2);

      const [raiden, partner] = await makeRaidens(2);
      await ensureTokenIsMonitored(raiden);

      const tokenNetworkContract = raiden.deps.getTokenNetworkContract(tokenNetwork);
      const tx: ContractTransaction = {
        hash: makeHash(),
        confirmations: 1,
        nonce: 1,
        gasLimit: bigNumberify(1e6),
        gasPrice: bigNumberify(2e10),
        value: Zero,
        data: '0x',
        chainId: raiden.deps.network.chainId,
        from: raiden.address,
        wait: jest.fn().mockResolvedValue({ byzantium: true, status: 1 }),
      };
      tokenNetworkContract.functions.openChannel.mockResolvedValue(tx);

      raiden.store.dispatch(
        channelOpen.request({ settleTimeout }, { tokenNetwork, partner: partner.address }),
      );
      await waitBlock();

      // result is undefined on success as the respective channelOpen.success is emitted by the
      // tokenMonitoredEpic, which monitors the blockchain for ChannelOpened events
      expect(tokenNetworkContract.functions.openChannel).toHaveBeenCalledTimes(1);
      expect(tx.wait).toHaveBeenCalledTimes(1);
    });
  });

  test.only('channelOpenedEpic', async () => {
    expect.assertions(1);

    const [raiden, partner] = await makeRaidens(2);
    await ensureTokenIsMonitored(raiden);

    raiden.store.dispatch(
      channelOpen.success(
        {
          id,
          settleTimeout,
          isFirstParticipant,
          token,
          txHash,
          txBlock: openBlock,
          confirmed: true,
        },
        { tokenNetwork, partner: partner.address },
      ),
    );

    expect(raiden.output).toContainEqual(
      channelMonitor({ id, fromBlock: openBlock }, { tokenNetwork, partner: partner.address }),
    );
  });

  describe.only('channelMonitoredEpic', () => {
    const idEncoded = defaultAbiCoder.encode(['uint256'], [id]);
    const depositEncoded = defaultAbiCoder.encode(['uint256'], [deposit]);

    function getMonitoredFilter(tokenNetworkContract: TokenNetwork): Filter {
      return {
        address: tokenNetworkContract.address,
        topics: [
          [
            tokenNetworkContract.interface.events.ChannelNewDeposit.topic,
            tokenNetworkContract.interface.events.ChannelWithdraw.topic,
            tokenNetworkContract.interface.events.ChannelClosed.topic,
            tokenNetworkContract.interface.events.ChannelSettled.topic,
          ],
          [idEncoded],
        ],
      };
    }

    test('initial monitor with past$ own ChannelNewDeposit event', async () => {
      expect.assertions(1);

      const [raiden, partner] = await makeRaidens(2);
      const tokenNetworkContract = raiden.deps.getTokenNetworkContract(tokenNetwork);

      raiden.deps.provider.getLogs.mockResolvedValue([
        makeLog({
          blockNumber: openBlock + 1,
          filter: tokenNetworkContract.filters.ChannelNewDeposit(id, raiden.address, null),
          data: depositEncoded, // non-indexed total_deposit = 1023 goes in data
        }),
      ]);
      await ensureChannelIsOpen([raiden, partner]);
      raiden.store.dispatch(
        channelMonitor({ id, fromBlock: openBlock }, { tokenNetwork, partner: partner.address }),
      );
      await waitBlock();

      expect(raiden.output).toContainEqual(
        channelDeposit.success(
          {
            id,
            participant: raiden.address,
            totalDeposit: deposit,
            txHash: expect.any(String),
            txBlock: openBlock + 1,
            confirmed: undefined,
          },
          { tokenNetwork, partner: partner.address },
        ),
      );
    });

    test('already monitored with new$ partner ChannelNewDeposit event', async () => {
      expect.assertions(1);

      const [raiden, partner] = await makeRaidens(2);
      const tokenNetworkContract = raiden.deps.getTokenNetworkContract(tokenNetwork);

      await ensureChannelIsOpen([raiden, partner]);
      raiden.store.dispatch(
        channelMonitor({ id, fromBlock: openBlock }, { tokenNetwork, partner: partner.address }),
      );
      await waitBlock(openBlock + 2);
      raiden.deps.provider.emit(
        getMonitoredFilter(tokenNetworkContract),
        makeLog({
          blockNumber: openBlock + 2,
          filter: tokenNetworkContract.filters.ChannelNewDeposit(id, partner.address, null),
          data: depositEncoded, // non-indexed total_deposit = 1023 goes in data
        }),
      );
      await waitBlock();

      expect(raiden.output).toContainEqual(
        channelDeposit.success(
          {
            id,
            participant: partner.address,
            totalDeposit: deposit,
            txHash: expect.any(String),
            txBlock: openBlock + 2,
            confirmed: undefined,
          },
          { tokenNetwork, partner: partner.address },
        ),
      );
    });

    test('new$ partner ChannelWithdraw event', async () => {
      expect.assertions(1);
      const withdraw = bigNumberify(300) as UInt<32>;
      const withdrawEncoded = defaultAbiCoder.encode(['uint256'], [withdraw]);

      const [raiden, partner] = await makeRaidens(2);
      const tokenNetworkContract = raiden.deps.getTokenNetworkContract(tokenNetwork);

      await ensureChannelIsOpen([raiden, partner]);
      raiden.store.dispatch(
        channelMonitor({ id, fromBlock: openBlock }, { tokenNetwork, partner: partner.address }),
      );
      await waitBlock(closeBlock - 1);
      raiden.deps.provider.emit(
        getMonitoredFilter(tokenNetworkContract),
        makeLog({
          blockNumber: closeBlock - 1,
          transactionHash: txHash,
          filter: tokenNetworkContract.filters.ChannelWithdraw(id, partner.address, null),
          data: withdrawEncoded, // non-indexed totalWithdraw
        }),
      );
      await waitBlock();

      expect(raiden.output).toContainEqual(
        channelWithdrawn(
          {
            id,
            participant: partner.address,
            totalWithdraw: withdraw,
            txHash,
            txBlock: closeBlock - 1,
            confirmed: undefined,
          },
          { tokenNetwork, partner: partner.address },
        ),
      );
    });

    test('new$ partner ChannelClosed event', async () => {
      expect.assertions(2);

      const [raiden, partner] = await makeRaidens(2);
      const tokenNetworkContract = raiden.deps.getTokenNetworkContract(tokenNetwork);

      await ensureChannelIsOpen([raiden, partner]);
      raiden.store.dispatch(
        channelMonitor({ id, fromBlock: openBlock }, { tokenNetwork, partner: partner.address }),
      );
      await waitBlock(closeBlock);
      raiden.deps.provider.emit(
        getMonitoredFilter(tokenNetworkContract),
        makeLog({
          blockNumber: closeBlock,
          transactionHash: txHash,
          filter: tokenNetworkContract.filters.ChannelClosed(id, partner.address, 11, null),
          data: HashZero, // non-indexed balance_hash
        }),
      );
      await waitBlock();

      expect(raiden.output).toContainEqual(
        channelClose.success(
          {
            id,
            participant: partner.address,
            txHash,
            txBlock: closeBlock,
            confirmed: undefined,
          },
          { tokenNetwork, partner: partner.address },
        ),
      );
      expect(raiden.store.getState().channels[channelKey({ tokenNetwork, partner })].state).toBe(
        ChannelState.closing,
      );
    });

    test('new$ ChannelSettled event', async () => {
      expect.assertions(9);
      const settleDataEncoded = defaultAbiCoder.encode(
        ['uint256', 'bytes32', 'uint256', 'bytes32'],
        [Zero, HashZero, Zero, HashZero],
      );

      const [raiden, partner] = await makeRaidens(2);
      const tokenNetworkContract = raiden.deps.getTokenNetworkContract(tokenNetwork);

      await ensureChannelIsClosed([raiden, partner]);
      raiden.store.dispatch(
        channelMonitor({ id, fromBlock: openBlock }, { tokenNetwork, partner: partner.address }),
      );
      await waitBlock(settleBlock);

      const filter = getMonitoredFilter(tokenNetworkContract);
      expect(raiden.deps.provider.on).toHaveBeenCalledWith(filter, expect.any(Function));
      expect(raiden.deps.provider.removeListener).not.toHaveBeenCalledWith(
        filter,
        expect.any(Function),
      );
      expect(raiden.deps.provider.listenerCount(filter)).toBe(1);

      const settleHash = makeHash();
      raiden.deps.provider.emit(
        filter,
        makeLog({
          blockNumber: settleBlock,
          transactionHash: settleHash,
          filter: tokenNetworkContract.filters.ChannelSettled(id, null, null, null, null),
          data: settleDataEncoded, // participants amounts aren't indexed, so they go in data
        }),
      );
      await waitBlock();

      expect(raiden.output).toContainEqual(
        channelSettle.success(
          { id, txHash: settleHash, txBlock: settleBlock, confirmed: undefined, locks: [] },
          { tokenNetwork, partner: partner.address },
        ),
      );

      await waitBlock(settleBlock + 2 * confirmationBlocks);
      expect(raiden.output).toContainEqual(
        channelSettle.success(
          { id, txHash: settleHash, txBlock: expect.any(Number), confirmed: true, locks: [] },
          { tokenNetwork, partner: partner.address },
        ),
      );

      // ensure ChannelSettledAction completed channel monitoring and unsubscribed from events
      expect(raiden.deps.provider.removeListener).toHaveBeenCalledWith(
        filter,
        expect.any(Function),
      );
      expect(raiden.deps.provider.listenerCount(filter)).toBe(0);

      // ensure channel state is moved from 'channels' to 'oldChannels'
      expect(channelKey({ tokenNetwork, partner }) in raiden.store.getState().channels).toBe(
        false,
      );
      expect(
        channelUniqueKey({ id, tokenNetwork, partner }) in raiden.store.getState().oldChannels,
      ).toBe(true);
    });
  });

  describe.only('channelDepositEpic', () => {
    test('fails if channel.state !== "open" or missing', async () => {
      expect.assertions(1);

      const [raiden, partner] = await makeRaidens(2);
      raiden.store.dispatch(
        channelDeposit.request({ deposit }, { tokenNetwork, partner: partner.address }),
      );
      await waitBlock();

      expect(raiden.output).toContainEqual(
        channelDeposit.failure(expect.any(Error), { tokenNetwork, partner: partner.address }),
      );
    });

    test('approve tx fails', async () => {
      expect.assertions(3);

      const [raiden, partner] = await makeRaidens(2);
      await ensureChannelIsOpen([raiden, partner]);

      const tokenContract = raiden.deps.getTokenContract(token);
      const approveTx: ContractTransaction = {
        hash: txHash,
        confirmations: 1,
        nonce: 1,
        gasLimit: bigNumberify(1e6),
        gasPrice: bigNumberify(2e10),
        value: Zero,
        data: '0x',
        chainId: raiden.deps.network.chainId,
        from: raiden.address,
        wait: jest.fn().mockResolvedValue({ byzantium: true, status: 0 }),
      };
      tokenContract.functions.approve.mockResolvedValue(approveTx);

      raiden.store.dispatch(
        channelDeposit.request({ deposit }, { tokenNetwork, partner: partner.address }),
      );
      await waitBlock();

      expect(raiden.output).toContainEqual(
        channelDeposit.failure(expect.any(Error), { tokenNetwork, partner: partner.address }),
      );
      expect(tokenContract.functions.approve).toHaveBeenCalledTimes(1);
      expect(tokenContract.functions.approve).toHaveBeenCalledWith(tokenNetwork, deposit);
    });

    test('setTotalDeposit tx fails', async () => {
      expect.assertions(1);

      const [raiden, partner] = await makeRaidens(2);
      await ensureChannelIsOpen([raiden, partner]);

      const tokenContract = raiden.deps.getTokenContract(token);
      const tokenNetworkContract = raiden.deps.getTokenNetworkContract(tokenNetwork);

      const approveTx: ContractTransaction = {
        hash: makeHash(),
        confirmations: 1,
        nonce: 1,
        gasLimit: bigNumberify(1e6),
        gasPrice: bigNumberify(2e10),
        value: Zero,
        data: '0x',
        chainId: raiden.deps.network.chainId,
        from: raiden.address,
        wait: jest.fn().mockResolvedValue({ status: 1 }),
      };
      tokenContract.functions.approve.mockResolvedValue(approveTx);

      const setTotalDepositTx: ContractTransaction = {
        hash: makeHash(),
        confirmations: 1,
        nonce: 2,
        gasLimit: bigNumberify(1e6),
        gasPrice: bigNumberify(2e10),
        value: Zero,
        data: '0x',
        chainId: raiden.deps.network.chainId,
        from: raiden.address,
        wait: jest.fn().mockResolvedValue({ status: 0 }),
      };
      tokenNetworkContract.functions.setTotalDeposit.mockResolvedValue(setTotalDepositTx);

      raiden.store.dispatch(
        channelDeposit.request({ deposit }, { tokenNetwork, partner: partner.address }),
      );
      await waitBlock();

      expect(raiden.output).toContainEqual(
        channelDeposit.failure(expect.any(Error), { tokenNetwork, partner: partner.address }),
      );
    });

    test('success', async () => {
      expect.assertions(6);

      const prevDeposit = bigNumberify(330) as UInt<32>;
      const [raiden, partner] = await makeRaidens(2);
      await ensureChannelIsDeposited([raiden, partner], prevDeposit);

      const tokenContract = raiden.deps.getTokenContract(token);
      const tokenNetworkContract = raiden.deps.getTokenNetworkContract(tokenNetwork);

      const approveTx: ContractTransaction = {
        hash: makeHash(),
        confirmations: 1,
        nonce: 1,
        gasLimit: bigNumberify(1e6),
        gasPrice: bigNumberify(2e10),
        value: Zero,
        data: '0x',
        chainId: raiden.deps.network.chainId,
        from: raiden.address,
        wait: jest.fn().mockResolvedValue({ status: 1 }),
      };
      tokenContract.functions.approve.mockResolvedValue(approveTx);

      const setTotalDepositTx: ContractTransaction = {
        hash: makeHash(),
        confirmations: 1,
        nonce: 2,
        gasLimit: bigNumberify(1e6),
        gasPrice: bigNumberify(2e10),
        value: Zero,
        data: '0x',
        chainId: raiden.deps.network.chainId,
        from: raiden.address,
        wait: jest.fn().mockResolvedValue({ status: 1 }),
      };
      tokenNetworkContract.functions.setTotalDeposit.mockResolvedValue(setTotalDepositTx);
      tokenNetworkContract.functions.getChannelParticipantInfo.mockResolvedValue([
        prevDeposit,
        Zero,
        true,
        '',
        Zero,
        '',
        Zero,
      ]);

      raiden.store.dispatch(
        channelDeposit.request({ deposit }, { tokenNetwork, partner: partner.address }),
      );
      await waitBlock();

      // result is undefined on success as the respective channelDeposit.success is emitted by the
      // channelMonitoredEpic, which monitors the blockchain for ChannelNewDeposit events
      expect(raiden.output).not.toContainEqual(
        channelDeposit.failure(expect.any(Error), { tokenNetwork, partner: partner.address }),
      );
      expect(tokenContract.functions.approve).toHaveBeenCalledTimes(1);
      expect(approveTx.wait).toHaveBeenCalledTimes(1);
      expect(tokenNetworkContract.functions.setTotalDeposit).toHaveBeenCalledTimes(1);
      expect(tokenNetworkContract.functions.setTotalDeposit).toHaveBeenCalledWith(
        id,
        raiden.address,
        deposit.add(prevDeposit),
        partner.address,
      );
      expect(setTotalDepositTx.wait).toHaveBeenCalledTimes(1);
    });
  });

  describe('channelCloseEpic', () => {
    let depsMock: ReturnType<typeof raidenEpicDeps>;
    let tokenNetworkContract: ReturnType<typeof epicFixtures>['tokenNetworkContract'],
      partner: ReturnType<typeof epicFixtures>['partner'],
      partnerSigner: ReturnType<typeof epicFixtures>['partnerSigner'],
      action$: ReturnType<typeof epicFixtures>['action$'],
      state$: ReturnType<typeof epicFixtures>['state$'];

    beforeEach(async () => {
      depsMock = raidenEpicDeps();
      ({ tokenNetworkContract, partner, partnerSigner, action$, state$ } = epicFixtures(depsMock));

      [
        tokenMonitored({ token, tokenNetwork, fromBlock: 1 }),
        channelOpen.success(
          {
            id,
            settleTimeout,
            isFirstParticipant,
            token,
            txHash,
            txBlock: openBlock,
            confirmed: true,
          },
          { tokenNetwork, partner },
        ),
        newBlock({ blockNumber: closeBlock }),
      ].forEach((a) => action$.next(a));

      // put a received & unlocked transfer from partner in state
      const { state, config } = await depsMock.latest$.pipe(first()).toPromise();
      const secret = makeSecret();
      const secrethash = getSecrethash(secret);
      const amount = bigNumberify(10) as UInt<32>;
      const direction = Direction.RECEIVED;
      const expiration = bigNumberify(state.blockNumber + config.revealTimeout * 2) as UInt<32>;
      const lock = {
        secrethash,
        amount,
        expiration,
      };
      const transf = await signMessage(
        partnerSigner,
        {
          type: MessageType.LOCKED_TRANSFER,
          payment_identifier: makePaymentId(),
          message_identifier: makeMessageId(),
          chain_id: bigNumberify(depsMock.network.chainId) as UInt<32>,
          token,
          token_network_address: tokenNetwork,
          recipient: depsMock.address,
          target: depsMock.address,
          initiator: partner,
          channel_identifier: bigNumberify(id) as UInt<32>,
          metadata: { routes: [{ route: [depsMock.address] }] },
          lock,
          locksroot: getLocksroot([lock]),
          nonce: One as UInt<8>,
          transferred_amount: Zero as UInt<32>,
          locked_amount: lock.amount,
        },
        depsMock,
      );

      const unlock = await signMessage(
        partnerSigner,
        {
          type: MessageType.UNLOCK,
          payment_identifier: transf.payment_identifier,
          message_identifier: makeMessageId(),
          chain_id: transf.chain_id,
          token_network_address: tokenNetwork,
          channel_identifier: transf.channel_identifier,
          nonce: transf.nonce.add(1) as UInt<8>,
          transferred_amount: transf.transferred_amount.add(amount) as UInt<32>,
          locked_amount: transf.locked_amount.sub(amount) as UInt<32>,
          locksroot: getLocksroot([]),
          secret,
        },
        depsMock,
      );

      [
        transferSigned(
          {
            message: transf,
            fee: Zero as Int<32>,
          },
          { secrethash, direction },
        ),
        transferUnlock.success({ message: unlock }, { secrethash, direction }),
      ].forEach((a) => action$.next(a));
    });

    afterEach(() => {
      jest.clearAllMocks();
      action$.complete();
      state$.complete();
      depsMock.latest$.complete();
    });

    test('fails if there is no open channel with partner on tokenNetwork', async () => {
      // there's a channel already opened in state
      const action$ = of<RaidenAction>(channelClose.request(undefined, { tokenNetwork, partner })),
        state$ = of<RaidenState>(state);

      await expect(channelCloseEpic(action$, state$, depsMock).toPromise()).resolves.toEqual(
        channelClose.failure(expect.any(Error), { tokenNetwork, partner }),
      );
    });

    test('fails if channel.state !== "open"|"closing"', async () => {
      // there's a channel already opened in state
      const curState = [
        tokenMonitored({ token, tokenNetwork, fromBlock: 1 }),
        // channel is in 'opening' state
        channelOpen.request({ settleTimeout }, { tokenNetwork, partner }),
      ].reduce(raidenReducer, state);
      const action$ = of<RaidenAction>(channelClose.request(undefined, { tokenNetwork, partner })),
        state$ = of<RaidenState>(curState);

      await expect(channelCloseEpic(action$, state$, depsMock).toPromise()).resolves.toEqual(
        channelClose.failure(expect.any(Error), { tokenNetwork, partner }),
      );
    });

    test('closeChannel tx fails', async () => {
      const closeTx: ContractTransaction = {
        hash: txHash,
        confirmations: 1,
        nonce: 2,
        gasLimit: bigNumberify(1e6),
        gasPrice: bigNumberify(2e10),
        value: Zero,
        data: '0x',
        chainId: depsMock.network.chainId,
        from: depsMock.address,
        wait: jest.fn().mockResolvedValue({ byzantium: true, status: 0 }),
      };
      tokenNetworkContract.functions.closeChannel.mockResolvedValueOnce(closeTx);

      const promise = channelCloseEpic(action$, state$, depsMock).toPromise();
      action$.next(channelClose.request(undefined, { tokenNetwork, partner }));
      action$.complete();

      await expect(promise).resolves.toEqual(
        channelClose.failure(expect.any(Error), { tokenNetwork, partner }),
      );
    });

    test('success', async () => {
      const closeTx: ContractTransaction = {
        hash: txHash,
        confirmations: 1,
        nonce: 3,
        gasLimit: bigNumberify(1e6),
        gasPrice: bigNumberify(2e10),
        value: Zero,
        data: '0x',
        chainId: depsMock.network.chainId,
        from: depsMock.address,
        wait: jest.fn().mockResolvedValue({ byzantium: true, status: 1 }),
      };
      tokenNetworkContract.functions.closeChannel.mockResolvedValueOnce(closeTx);

      const promise = channelCloseEpic(action$, state$, depsMock).toPromise();
      action$.next(channelClose.request(undefined, { tokenNetwork, partner }));
      action$.complete();

      // result is undefined on success as the respective channelClose.success is emitted by the
      // channelMonitoredEpic, which monitors the blockchain for channel events
      await expect(promise).resolves.toBeUndefined();
      expect(tokenNetworkContract.functions.closeChannel).toHaveBeenCalledTimes(1);
      expect(tokenNetworkContract.functions.closeChannel).toHaveBeenCalledWith(
        id,
        partner,
        depsMock.address,
        expect.any(String), // balance_hash
        expect.any(BigNumber), // nonce
        expect.any(String), // additional_hash
        expect.any(String), // non_closing_signature
        expect.any(String), // closing_signature
      );
      expect(closeTx.wait).toHaveBeenCalledTimes(1);
    });

    test('channelUpdateEpic', async () => {
      const promise = channelUpdateEpic(action$, state$, depsMock).toPromise();
      [
        channelClose.success(
          {
            id,
            participant: partner,
            txHash,
            txBlock: closeBlock,
            confirmed: true,
          },
          { tokenNetwork, partner },
        ),
        newBlock({ blockNumber: closeBlock + 1 }),
        newBlock({ blockNumber: closeBlock + 2 }),
      ].forEach((a) => action$.next(a));

      setTimeout(() => action$.complete(), 10);
      await expect(promise).resolves.toBeUndefined();

      expect(tokenNetworkContract.functions.updateNonClosingBalanceProof).toHaveBeenCalledTimes(1);
    });
  });

  describe('channelSettleEpic', () => {
    const openBlock = 121,
      closeBlock = 125,
      settleBlock = closeBlock + settleTimeout + 1;

    test('fails if there is no channel with partner on tokenNetwork', async () => {
      // there's a channel already opened in state
      const action$ = of<RaidenAction>(
          channelSettle.request(undefined, { tokenNetwork, partner }),
        ),
        state$ = of<RaidenState>(state);

      await expect(channelSettleEpic(action$, state$, depsMock).toPromise()).resolves.toEqual(
        channelSettle.failure(expect.any(Error), { tokenNetwork, partner }),
      );
    });

    test('fails if channel.state !== "settleable|settling"', async () => {
      // there's a channel in closed state, but not yet settleable
      const curState = [
        tokenMonitored({ token, tokenNetwork, fromBlock: 1 }),
        channelOpen.success(
          {
            id,
            settleTimeout,
            isFirstParticipant,
            token,
            txHash,
            txBlock: openBlock,
            confirmed: true,
          },
          { tokenNetwork, partner },
        ),
        newBlock({ blockNumber: closeBlock }),
        channelClose.success(
          {
            id,
            participant: depsMock.address,
            txHash,
            txBlock: closeBlock,
            confirmed: true,
          },
          { tokenNetwork, partner },
        ),
      ].reduce(raidenReducer, state);
      const action$ = of<RaidenAction>(
          channelSettle.request(undefined, { tokenNetwork, partner }),
        ),
        state$ = of<RaidenState>(curState);

      await expect(channelSettleEpic(action$, state$, depsMock).toPromise()).resolves.toEqual(
        channelSettle.failure(expect.any(Error), { tokenNetwork, partner }),
      );
    });

    test('settleChannel tx fails', async () => {
      // there's a channel with partner in closed state and current block >= settleBlock
      const curState = [
        tokenMonitored({ token, tokenNetwork, fromBlock: 1 }),
        channelOpen.success(
          {
            id,
            settleTimeout,
            isFirstParticipant,
            token,
            txHash,
            txBlock: openBlock,
            confirmed: true,
          },
          { tokenNetwork, partner },
        ),
        newBlock({ blockNumber: closeBlock }),
        channelClose.success(
          {
            id,
            participant: depsMock.address,
            txHash,
            txBlock: closeBlock,
            confirmed: true,
          },
          { tokenNetwork, partner },
        ),
        newBlock({ blockNumber: settleBlock }),
        channelSettleable({ settleableBlock: settleBlock }, { tokenNetwork, partner }),
      ].reduce(raidenReducer, state);
      const action$ = of<RaidenAction>(
          channelSettle.request(undefined, { tokenNetwork, partner }),
        ),
        state$ = of<RaidenState>(curState);

      const settleTx: ContractTransaction = {
        hash: txHash,
        confirmations: 1,
        nonce: 2,
        gasLimit: bigNumberify(1e6),
        gasPrice: bigNumberify(2e10),
        value: Zero,
        data: '0x',
        chainId: depsMock.network.chainId,
        from: depsMock.address,
        wait: jest.fn().mockResolvedValue({ byzantium: true, status: 0 }),
      };
      tokenNetworkContract.functions.settleChannel.mockResolvedValueOnce(settleTx);

      await expect(channelSettleEpic(action$, state$, depsMock).toPromise()).resolves.toEqual(
        channelSettle.failure(expect.any(Error), { tokenNetwork, partner }),
      );
    });

    test('success', async () => {
      // there's a channel with partner in closed state and current block >= settleBlock
      const curState = [
        tokenMonitored({ token, tokenNetwork, fromBlock: 1 }),
        channelOpen.success(
          {
            id,
            settleTimeout,
            isFirstParticipant,
            token,
            txHash,
            txBlock: openBlock,
            confirmed: true,
          },
          { tokenNetwork, partner },
        ),
        newBlock({ blockNumber: closeBlock }),
        channelClose.success(
          {
            id,
            participant: depsMock.address,
            txHash,
            txBlock: closeBlock,
            confirmed: true,
          },
          { tokenNetwork, partner },
        ),
        newBlock({ blockNumber: settleBlock }),
        channelSettleable({ settleableBlock: settleBlock }, { tokenNetwork, partner }),
      ].reduce(raidenReducer, state);
      const action$ = of<RaidenAction>(
          channelSettle.request(undefined, { tokenNetwork, partner }),
        ),
        state$ = of<RaidenState>(curState);

      const settleTx: ContractTransaction = {
        hash: txHash,
        confirmations: 1,
        nonce: 2,
        gasLimit: bigNumberify(1e6),
        gasPrice: bigNumberify(2e10),
        value: Zero,
        data: '0x',
        chainId: depsMock.network.chainId,
        from: depsMock.address,
        wait: jest.fn().mockResolvedValue({ byzantium: true, status: 1 }),
      };
      tokenNetworkContract.functions.settleChannel.mockResolvedValueOnce(settleTx);

      // result is undefined on success as the respective ChannelSettledAction is emitted by the
      // channelMonitoredEpic, which monitors the blockchain for channel events
      await expect(
        channelSettleEpic(action$, state$, depsMock).toPromise(),
      ).resolves.toBeUndefined();
      expect(tokenNetworkContract.functions.settleChannel).toHaveBeenCalledTimes(1);
      expect(tokenNetworkContract.functions.settleChannel).toHaveBeenCalledWith(
        id,
        depsMock.address,
        Zero, // self transfered amount
        Zero, // self locked amount
        HashZero, // self locksroot
        partner,
        Zero, // partner transfered amount
        Zero, // partner locked amount
        HashZero, // partner locksroot
      );
      expect(settleTx.wait).toHaveBeenCalledTimes(1);
    });
  });

  test('channelUnlockEpic', async () => {
    expect.assertions(4);
    const tokenNetworkContract = depsMock.getTokenNetworkContract(tokenNetwork);

    tokenNetworkContract.functions.unlock.mockResolvedValueOnce({
      hash: txHash,
      confirmations: 1,
      nonce: 2,
      gasLimit: bigNumberify(1e6),
      gasPrice: bigNumberify(2e10),
      value: Zero,
      data: '0x',
      chainId: depsMock.network.chainId,
      from: depsMock.address,
      wait: jest.fn().mockResolvedValue({ byzantium: true, status: 0 }),
    });

    await expect(
      channelUnlockEpic(
        of(
          channelSettle.success(
            {
              id,
              txHash,
              txBlock: 129,
              confirmed: true,
              locks: [
                {
                  amount: bigNumberify(10) as UInt<32>,
                  expiration: bigNumberify(128) as UInt<32>,
                  secrethash: getSecrethash(makeSecret()),
                },
              ],
            },
            { tokenNetwork, partner },
          ),
        ),
        depsMock.latest$.pipe(pluck('state')),
        depsMock,
      ).toPromise(),
    ).resolves.toBeUndefined();

    tokenNetworkContract.functions.unlock.mockResolvedValueOnce({
      hash: txHash,
      confirmations: 1,
      nonce: 2,
      gasLimit: bigNumberify(1e6),
      gasPrice: bigNumberify(2e10),
      value: Zero,
      data: '0x',
      chainId: depsMock.network.chainId,
      from: depsMock.address,
      wait: jest.fn().mockResolvedValue({ byzantium: true, status: 1 }),
    });

    await expect(
      channelUnlockEpic(
        of(
          channelSettle.success(
            {
              id,
              txHash,
              txBlock: 129,
              confirmed: true,
              locks: [
                {
                  amount: bigNumberify(10) as UInt<32>,
                  expiration: bigNumberify(128) as UInt<32>,
                  secrethash: getSecrethash(makeSecret()),
                },
              ],
            },
            { tokenNetwork, partner },
          ),
        ),
        depsMock.latest$.pipe(pluck('state')),
        depsMock,
      ).toPromise(),
    ).resolves.toBeUndefined();

    expect(tokenNetworkContract.functions.unlock).toHaveBeenCalledTimes(2);
    expect(tokenNetworkContract.functions.unlock).toHaveBeenCalledWith(
      id,
      depsMock.address,
      partner,
      expect.any(Uint8Array),
    );
  });
});
