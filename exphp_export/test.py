try:
    import binaryninja as bn
    from binaryninja import BinaryView
except ImportError:
    raise ImportError("These tests cannot be run standalone.  You must call exphp_export.run_tests() from inside binary ninja.")

__all__ = ['run_tests']

# NOTE: Because we're inside binaryninja we cannot use unittest or pytest.
#       We have to do everything ourselves.
def run_tests():
    defs = globals()
    for name in defs:
        if name.startswith('test_'):
            func = defs[name]
            if callable(func):
                print(func.__name__)
                func()

# ==============================================================================

def bv_from_c_defs(c_code: str) -> BinaryView:
    bv = BinaryView()
    types_to_add = bv.parse_types_from_string(c_code)
    for name, ty in types_to_add.types.items():
        bv.define_user_type(name, ty)
    return bv

def test_lookup_named_type_definition():
    from .common import lookup_named_type_definition

    bv = bv_from_c_defs('''
        typedef int32_t Typedef1;
        typedef Typedef1 Typedef2;
        typedef Typedef2 Typedef3;

        struct S { int x; }
        typedef struct S Typedef1s;
        typedef Typedef1s Typedef2s;
        typedef Typedef2s Typedef3s;
    ''')

    def expect_typedef(name):
        kind, expanded_ty = lookup_named_type_definition(bv, name)
        assert_equal(kind, 'typedef')
        return expanded_ty

    assert_equal(str(expect_typedef('Typedef1')), 'int32_t')
    assert_equal(str(expect_typedef('Typedef2')), 'Typedef1')  # This one is the nasty corner case
    assert_equal(str(expect_typedef('Typedef3')), 'Typedef2')

    assert_equal(lookup_named_type_definition(bv, 'S'), ('struct', None))
    assert_equal(str(expect_typedef('Typedef1s')), 'struct S')
    assert_equal(str(expect_typedef('Typedef2s')), 'Typedef1s')
    assert_equal(str(expect_typedef('Typedef3s')), 'Typedef2s')

def assert_equal(actual, expected):
    if actual != expected:
        print('  actual: ', actual)
        print('expected: ', expected)
        assert False

def assert_attrs_eq(actual, expected):
    for k in expected:
        try:
            if not hasattr(actual, k) or getattr(actual, k) != expected[k]:
                print('  actual: ', actual)
                print('expected: ', expected)
                print(' bad key: ', k)
                print(' hasattr: ', hasattr(actual, k))
                assert False, 'not a subset of expected'
        except:
            raise ValueError(repr((actual, expected)))

def testcase(name):
    print(f' - {name}')

def test_structure_padding():
    from .export_types import _structure_fields, GAP_MEMBER_NAME, PADDING_MEMBER_NAME, END_MEMBER_NAME

    def run_on_struct(size, data):
        bv = bn.BinaryView()
        structure = bn.Structure()
        structure.width = size
        for i, (offset, ty) in enumerate(data):
            if isinstance(ty, str):
                ty = bv.parse_type_string(ty)[0]
            structure.insert(offset, ty, f'field_{i}')
        structure.alignment = max([member.type.alignment for member in structure.members], default=1)  # why do i have to do this manually
        return list(_structure_fields(structure, ignore=None))

    testcase('gap that is padding')
    members = run_on_struct(0x08, [(0x00, 'int16_t'), (0x04, 'int32_t')])
    assert_attrs_eq(members[1], {'offset': 0x02, 'name': PADDING_MEMBER_NAME})
    assert_attrs_eq(members[2], {'offset': 0x04, 'name': 'field_1'})

    testcase('gap that isn\'t padding because of alignment that follows')
    members = run_on_struct(0x0c, [(0x00, 'int16_t'), (0x04, 'int16_t'), (0x08, 'int32_t')])
    assert_attrs_eq(members[1], {'offset': 0x02, 'name': GAP_MEMBER_NAME})

    testcase("gap that isn't padding because it's too large")
    members = run_on_struct(0x0c, [(0x00, 'int16_t'), (0x08, 'int32_t')])
    assert_attrs_eq(members[1], {'offset': 0x02, 'name': GAP_MEMBER_NAME})
    assert_attrs_eq(members[2], {'offset': 0x08, 'name': 'field_1'})

    testcase("end padding")
    members = run_on_struct(0x08, [(0x00, 'int32_t'), (0x04, 'int16_t')])
    assert_attrs_eq(members[2], {'offset': 0x06, 'name': PADDING_MEMBER_NAME})
    assert_attrs_eq(members[3], {'offset': 0x08, 'name': END_MEMBER_NAME})

    testcase("no end padding")
    members = run_on_struct(0x06, [(0x00, 'int16_t'), (0x04, 'int16_t')])
    assert_attrs_eq(members[2], {'offset': 0x04, 'name': 'field_1'})
    assert_attrs_eq(members[3], {'offset': 0x06, 'name': END_MEMBER_NAME})

    testcase("no members")
    members = run_on_struct(0x08, [])
    assert_attrs_eq(members[0], {'offset': 0x00, 'name': GAP_MEMBER_NAME})
    assert_attrs_eq(members[1], {'offset': 0x08, 'name': END_MEMBER_NAME})

    testcase("no members and ZST")
    members = run_on_struct(0x00, [])
    assert_attrs_eq(members[0], {'offset': 0x00, 'name': END_MEMBER_NAME})

    testcase("ZST with member.")
    members = run_on_struct(0x00, [(0x00, bn.Type.array(bn.Type.char(), 0))])
    assert_attrs_eq(members[0], {'offset': 0x00, 'name': 'field_0'})
    assert_attrs_eq(members[1], {'offset': 0x00, 'name': END_MEMBER_NAME})

    testcase("gap before first member")
    members = run_on_struct(0x08, [(0x04, 'int32_t')])
    assert_attrs_eq(members[0], {'offset': 0x00, 'name': GAP_MEMBER_NAME})
    assert_attrs_eq(members[1], {'offset': 0x04, 'name': 'field_0'})


def test_packed_struct():
    from .export_types import _structure_fields, GAP_MEMBER_NAME, END_MEMBER_NAME

    def run_on_struct(size, data):
        bv = bn.BinaryView()
        structure = bn.Structure()
        structure.packed = True
        structure.width = size
        for i, (offset, typestr) in enumerate(data):
            structure.insert(offset, bv.parse_type_string(typestr)[0], f'field_{i}')
        return list(_structure_fields(structure, ignore=None))

    testcase('smoke test')
    members = run_on_struct(0x0a, [(0x00, 'int16_t'), (0x04, 'int32_t'), (0x08, 'int16_t')])
    assert_attrs_eq(members[0], {'offset': 0x00, 'name': 'field_0'})
    assert_attrs_eq(members[1], {'offset': 0x02, 'name': GAP_MEMBER_NAME})
    assert_attrs_eq(members[2], {'offset': 0x04, 'name': 'field_1'})
    assert_attrs_eq(members[3], {'offset': 0x08, 'name': 'field_2'})
    assert_attrs_eq(members[4], {'offset': 0x0a, 'name': END_MEMBER_NAME})

    testcase('end gap')
    members = run_on_struct(0x0a, [(0x00, 'int16_t')])
    assert_attrs_eq(members[0], {'offset': 0x00, 'name': 'field_0'})
    assert_attrs_eq(members[1], {'offset': 0x02, 'name': GAP_MEMBER_NAME})
    assert_attrs_eq(members[2], {'offset': 0x0a, 'name': END_MEMBER_NAME})

def test_union():
    from .export_types import _structure_fields

    bv = bv_from_c_defs('''
        union Union {
            int32_t four;
            int16_t two;
        }
    ''')
    members = list(_structure_fields(bv.types['Union'].structure, ignore=None))
    assert_equal(len(members), 2)
    assert_attrs_eq(members[0], {'offset': 0x00, 'name': 'four'})
    assert_attrs_eq(members[1], {'offset': 0x00, 'name': 'two'})
