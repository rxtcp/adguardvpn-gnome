"""Lossless GVariant editing preserves signatures and every untouched NM field."""


def remove_entries(glib, serialized: str, patches: list[dict]) -> tuple[str, dict]:
    variant = glib.Variant.parse(glib.VariantType.new('a{sa{sv}}'), serialized, None, None)
    settings = {}
    for index in range(variant.n_children()):
        entry = variant.get_child_value(index)
        name, values = entry.get_child_value(0).unpack(), entry.get_child_value(1)
        fields = {}
        for field_index in range(values.n_children()):
            field = values.get_child_value(field_index)
            fields[field.get_child_value(0).unpack()] = field.get_child_value(1).get_variant()
        settings[name] = fields
    for patch in patches:
        original = settings[patch['setting']][patch['field']]
        if any(type(index) is not int or not 0 <= index < original.n_children() for index in patch['indices']):
            raise ValueError('The migration diff no longer matches the profile.')
        children = [original.get_child_value(index) for index in range(original.n_children()) if index not in patch['indices']]
        settings[patch['setting']][patch['field']] = glib.Variant.new_array(original.get_type().element(), children)
    result = glib.Variant('a{sa{sv}}', settings)
    return result.print_(True), result.unpack()
