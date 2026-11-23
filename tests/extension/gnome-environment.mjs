import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import {domainToASCII} from 'node:url';

export async function createEnvironment(options = {}) {
    const calls = [], notifications = [], warnings = [], timers = new Map();
    const processes = [], actors = [], commands = [];
    let clock = 1_000_000, nextId = 1, saved = options.saved, cancelled = false;
    const cancelHandlers = new Map();
    const dbusCalls = [], dbusResponses = [], dbusPending = [], dbusBusPending = [];
    class Actor {
        constructor(properties = {}) {
            this.children = []; this.handlers = new Map(); this.visible = true;
            this.reactive = true; this.checked = false; this.destroyed = false;
            Object.assign(this, properties); actors.push(this);
            if (properties.child) this.children.push(properties.child);
        }
        add_child(child) { this.children.push(child); child.parent = this; }
        insert_child_at_index(child, index) { this.children.splice(index, 0, child); child.parent = this; }
        get_children() { return [...this.children]; }
        connect(signal, callback) { this.handlers.set(signal, callback); return nextId++; }
        emit(signal, ...args) { return this.handlers.get(signal)?.(this, ...args); }
        hide() { this.visible = false; }
        show() { this.visible = true; }
        destroy() {
            this.destroyed = true;
            if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this);
            for (const child of [...this.children]) child.destroy();
        }
        set_child(child) { this.add_child(child); }
        set_policy(...policy) { this.policy = policy; }
        set_height(height) { this.height = height; }
        get_vadjustment() { return {set_value: value => { this.scroll = value; }}; }
        add(child) { this.add_child(child); }
        append(child) { this.add_child(child); }
        add_suffix(child) { this.add_child(child); }
        remove(child) { child.destroy(); }
        set_text(text) { this.text = text; this.emit('notify::text'); }
        get_text() { return this.text ?? ''; }
        set_sensitive(value) { this.sensitive = value; }
        set_label(label) { this.label = label; }
        set_selected(selected) { this.selected = selected; }
        get_selected() { return this.selected ?? 4294967295; }
        set_model(model) { this.model = model; }
        set_default_size(width, height) { this.width = width; this.height = height; }
        add_response(id, label) { (this.responses ??= new Map()).set(id, label); }
        set_response_appearance(id, appearance) { (this.appearances ??= new Map()).set(id, appearance); }
        set_default_response(id) { this.defaultResponse = id; }
        set_close_response(id) { this.closeResponse = id; }
        present() { this.visible = true; }
        update_property(properties, values) { this.accessible_name = values[0]; }
    }
    class Menu extends Actor {
        constructor() { super(); this.box = new Actor(); this.actions = []; }
        addMenuItem(item) { this.box.add_child(item); }
        addAction(text, callback) { const action = {text, callback}; this.actions.push(action); return action; }
        close() { this.open = false; }
    }
    class Toggle extends Actor { constructor(properties) { super(properties); this.menu = new Menu(); } }
    class Indicator extends Actor {
        constructor() { super(); this.quickSettingsItems = []; }
        _addIndicator() { const icon = new Actor(); this.add_child(icon); return icon; }
    }
    class Cancellable {
        constructor() { this.cancelled = false; this.ids = new Set(); }
        connect(callback) { const id = nextId++; cancelHandlers.set(id, callback); this.ids.add(id); return id; }
        disconnect(id) { cancelHandlers.delete(id); this.ids.delete(id); }
        is_cancelled() { return this.cancelled; }
        cancel() { this.cancelled = cancelled = true; for (const id of this.ids) cancelHandlers.get(id)?.(); }
    }
    class Variant {
        constructor(signature, values) { this.signature = signature; this.values = values; }
        deepUnpack() { return this.values; }
    }
    const dbusConnection = {
        call(destination, path, iface, method, parameters, type, flags, timeout, cancellable, callback) {
            const request = JSON.parse(parameters.deepUnpack()[0]);
            dbusCalls.push({destination, path, iface, method, request, timeout});
            const response = dbusResponses.shift() ?? {data: request.operation === 'list-providers' ? {providers: []} : {rules: []}};
            const complete = () => callback(dbusConnection, {response, cancellable});
            if (response.deferred) dbusPending.push(complete);
            else queueMicrotask(complete);
        },
        call_finish({response, cancellable}) {
            if (cancellable.is_cancelled()) throw new Error('Cancelled');
            if (response.error) throw new Error(response.error);
            const text = response.raw ?? JSON.stringify(response.envelope ?? {schema_version: 1, ok: true, data: response.data});
            return new Variant('(s)', response.values ?? [text]);
        },
    };
    const program = name => {
        if (options.programs) return options.programs[name] ?? null;
        return name === 'adguardvpn-cli' ? '/bin/adguardvpn-cli' : null;
    };
    const Gio = {
        BusType: {SYSTEM: 1}, DBusCallFlags: {NONE: 0},
        bus_get(type, cancellable, callback) {
            const complete = () => callback(null, {});
            if (options.busDeferred) dbusBusPending.push(complete);
            else queueMicrotask(complete);
        },
        bus_get_finish() { if (options.busError) throw new Error(options.busError); return dbusConnection; },
        Cancellable, FileIcon: Actor, SubprocessFlags: {NONE: 0, STDOUT_PIPE: 1, STDERR_PIPE: 2},
        File: {new_for_path: path => ({query_exists: () => (options.files ?? []).includes(path)})},
        Subprocess: {new(argv, flags) {
            calls.push({argv, flags});
            const response = commands.shift() ?? (argv.includes('status')
                ? {output: 'Disconnected'} : {output: ''});
            if (response.spawnError) throw new Error(response.spawnError);
            const process = {
                forced: false,
                force_exit() { this.forced = true; },
                get_successful() { return response.success !== false; },
                communicate_utf8_finish() {
                    if (response.finishError) throw new Error(response.finishError);
                    return [true, response.output ?? null, response.stderr ?? null];
                },
                communicate_utf8_async(_input, _cancel, callback) {
                    this.complete = () => callback(this, {});
                    if (!response.deferred) queueMicrotask(this.complete);
                },
            };
            processes.push(process); return process;
        }},
    };
    const GLib = {
        Variant, VariantType: {new: signature => signature}, hostname_to_ascii: domainToASCII,
        PRIORITY_DEFAULT: 0, SOURCE_REMOVE: false, SOURCE_CONTINUE: true,
        find_program_in_path: program, get_monotonic_time: () => clock,
        get_user_config_dir: () => '/config', build_filenamev: parts => parts.join('/'),
        path_get_dirname: path => path.slice(0, path.lastIndexOf('/')),
        mkdir_with_parents(path, mode) { if (options.saveError) throw new Error('Read-only'); this.mkdir = {path, mode}; },
        file_get_contents() { if (saved === undefined) throw new Error('Missing'); return [true, new TextEncoder().encode(saved)]; },
        file_set_contents(_path, content) { saved = content; },
        timeout_add_seconds(_priority, seconds, callback) { const id = nextId++; timers.set(id, {seconds, callback}); return id; },
        Source: {remove: id => timers.delete(id)},
    };
    let indicator;
    const Main = {
        notify: (...args) => notifications.push(args),
        layoutManager: {primaryMonitor: options.noMonitor ? null : {height: options.height ?? 900}},
        panel: {statusArea: {quickSettings: {addExternalIndicator: value => { indicator = value; }}}},
    };
    const gi = {Gio, GLib, GObject: {registerClass: type => type}, Clutter: {ActorAlign: {CENTER: 1}},
        St: {BoxLayout: Actor, Bin: Actor, Icon: Actor, Label: Actor, Button: Actor, ScrollView: Actor,
            PolicyType: {NEVER: 0, AUTOMATIC: 1}}};
    gi.Gtk = {Button: Actor, Label: Actor, TextBuffer: Actor, TextView: Actor, ScrolledWindow: Actor,
        WrapMode: {WORD_CHAR: 1}, Align: {CENTER: 1}, AccessibleRole: {BUTTON: 1}, AccessibleProperty: {LABEL: 1},
        StringList: {new: strings => new Actor({strings})},
        INVALID_LIST_POSITION: 4294967295};
    gi.Adw = {PreferencesPage: Actor, PreferencesGroup: Actor, PreferencesWindow: Actor,
        EntryRow: Actor, ComboRow: Actor, ActionRow: Actor, MessageDialog: Actor,
        ResponseAppearance: {DESTRUCTIVE: 2, SUGGESTED: 1}};
    let preferencesOpened = 0;
    const extensionBase = class {
        constructor() { this.dir = {get_child: () => ({get_child: () => ({})})}; }
        openPreferences() { preferencesOpened++; return Promise.resolve(); }
    };
    const imports = {
        'resource:///org/gnome/shell/extensions/extension.js': {Extension: extensionBase},
        'resource:///org/gnome/Shell/Extensions/js/extensions/prefs.js': {ExtensionPreferences: class {}},
        'resource:///org/gnome/shell/ui/main.js': Main,
        'resource:///org/gnome/shell/ui/popupMenu.js': {PopupMenuSection: Menu,
            PopupSeparatorMenuItem: class extends Actor { constructor(text) { super(); this.label = {text}; } }},
        'resource:///org/gnome/shell/ui/quickSettings.js': {QuickMenuToggle: Toggle, SystemIndicator: Indicator},
    };
    const context = vm.createContext({TextDecoder, TextEncoder,
        console: {warn: text => warnings.push(text), error: text => warnings.push(text)}});
    const modules = new Map();
    async function load(url) {
        const key = String(url);
        if (modules.has(key)) return modules.get(key);
        let module;
        if (key.startsWith('gi://') || key.startsWith('resource:')) {
            const exports = key.startsWith('gi://') ? {default: gi[key.slice(5)]} : imports[key];
            if (!exports) throw new Error(`Unexpected GNOME import: ${key}`);
            module = new vm.SyntheticModule(Object.keys(exports), function () {
                for (const [name, value] of Object.entries(exports)) this.setExport(name, value);
            }, {context, identifier: key});
        } else {
            const source = await readFile(new URL(key), 'utf8');
            module = new vm.SourceTextModule(source, {context, identifier: key});
        }
        modules.set(key, module);
        await module.link((specifier, parent) => load(specifier.startsWith('.') ? new URL(specifier, parent.identifier) : specifier));
        return module;
    }
    const entry = await load(new URL('../../dist/extension.js', import.meta.url));
    await entry.evaluate();
    const namespace = {...entry.namespace};
    const importModule = async path => {
        const module = await load(new URL(`../../dist/${path}`, import.meta.url));
        if (module.status !== 'evaluated') await module.evaluate();
        return module.namespace;
    };
    if (options.includeFunctions) {
        for (const path of ['domain/cli-output.js', 'domain/preferences.js', 'domain/locations.js',
            'domain/status.js', 'platform/preference-store.js', 'platform/subprocess.js', 'platform/terminal.js'])
            Object.assign(namespace, await importModule(path));
    }
    const extension = new entry.namespace.default();
    const settle = async () => { for (let i = 0; i < 6; i++) await new Promise(resolve => setImmediate(resolve)); };
    return {
        calls, notifications, warnings, timers, processes, commands, actors, Gio, GLib, Gtk: gi.Gtk, Adw: gi.Adw,
        entry: {namespace}, importModule, settle, createMenu: () => new Menu(),
        dbusCalls, dbusResponses, dbusPending, dbusBusPending, get preferencesOpened() { return preferencesOpened; },
        get saved() { return saved; }, get indicator() { return indicator; },
        get toggle() { return indicator.quickSettingsItems[0]; },
        get cancelled() { return cancelled; }, get cancelHandlerCount() { return cancelHandlers.size; },
        advance(seconds) { clock += seconds * 1_000_000; },
        async start() { extension.enable(); await settle(); return this; },
        stop() { extension.disable(); },
        async click() { this.toggle.emit('clicked'); await settle(); },
        async refresh() { await this.toggle.refresh(); await settle(); },
        async press(text) {
            const actions = actors.flatMap(actor => actor.actions ?? []);
            const action = actions.find(action => action.text === text);
            if (action) action.callback();
            else {
                const button = actors.find(actor => !actor.destroyed && actor.handlers.has('clicked') &&
                    (actor.accessible_name === text || actor.label === text || actor.children.some(child => child.text === text || child.children?.some(label => label.text === text))));
                if (!button) throw new Error(`Button not found: ${text}`);
                button.emit('clicked');
            }
            await settle();
        },
    };
}

export const plain = value => JSON.parse(JSON.stringify(value));
