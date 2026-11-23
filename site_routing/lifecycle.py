"""Early protection and explicit administrative release, without D-Bus or DNS."""


def known_addresses(state: dict) -> list[str]:
    return sorted(set(state['kernel']['known']) |
                  {address for rule in state['rules'] for address in rule['addresses']} |
                  {item['address'] for item in [*state['kernel']['objects'], *state['kernel'].get('pending_objects', [])]})


def restore_guard(store, kernel) -> None:
    with store.lock():
        state = store.load()
        addresses = known_addresses(state)
        if not addresses and not state['rules']:
            return
        if addresses:
            kernel.block(addresses, state['installation_id'])


def check_empty(store) -> bool:
    with store.lock():
        state = store.load()
        return not state['rules'] and not known_addresses(state)


def release_all(store, kernel) -> None:
    with store.lock():
        state = store.load()
        addresses = known_addresses(state)
        if not addresses and not state['rules']:
            return
        if addresses:
            kernel.block(addresses, state['installation_id'])
        state['rules'] = []
        state['kernel']['known'] = addresses
        store.save(state)
        def checkpoint(journal):
            state['kernel'] = journal
            store.save(state)
        state['kernel'] = kernel.apply({}, state['kernel'], state['installation_id'], checkpoint=checkpoint)
        store.save(state)
        if state['kernel'].get('failures'):
            raise RuntimeError('Some owned policies could not be released; protection and pending intent are retained.')
