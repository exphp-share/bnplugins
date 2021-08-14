import touhouReverse as r

def load_map(bv, map_path):
    with r.recording_undo(bv) as rec:
        _load_map(bv, map_path)

def _load_map(bv, map_path):
    with open(map_path) as f:
        lines = list(f)
    lines = (line.strip() for line in lines)
    assert next(lines) == ''
    assert next(lines).split() == ['Start', 'Length', 'Name', 'Class']

    # segment_map = SegmentMap(bv)
    # while True:
    #     sector_line = next(lines)
    #     if sector_line == '':
    #         break
    #     start, length, _name, klass = sector_line.split()
    #     assert length[-1] == 'H'
    #     length = int(length[:-1], 16)
    #     segment, offset = parse_segmented_address(start)
    #     segment_map.add_region(klass, segment, offset, length)

    segment_map = {}
    while True:
        sector_line = next(lines)
        if sector_line == '':
            break
        start, _length, _name, klass = sector_line.split()
        segment, offset = parse_segmented_address(start)
        if offset == 0:
            segment_map[segment] = bv.sections[klass].start

    assert next(lines) == ''
    assert next(lines) == 'Detailed map of segments'
    assert next(lines) == ''
    while next(lines) != '':
        pass
    assert next(lines) == ''
    assert next(lines).split() == ['Address', 'Publics', 'by', 'Name']
    assert next(lines) == ''

    useful_count = 0
    while True:
        line = next(lines)
        if line == '':
            break

        address, name = line.split()
        segment, offset = parse_segmented_address(address)
        ea = offset + segment_map[segment]

        existing_name = get_name_at(bv, ea)
        if existing_name is None or 'sub_' in existing_name or 'data_' in existing_name:
            useful_count += 1
            if bv.get_functions_at(ea):
                r.name_function(bv, ea, name)
            elif bv.get_symbol_at(ea):
                r.name_symbol(bv, ea, name)
            else:
                r.add_label(bv, ea, name)
    print(f'{useful_count} useful entries')

def parse_segmented_address(s):
    section, offset = s.split(':')
    return int(section, 16), int(offset, 16)

def get_name_at(bv, addr):
    funcs = bv.get_functions_at(addr)
    if funcs:
        return funcs[0].name
    symbol = bv.get_symbol_at(addr)
    if symbol:
        return symbol.name
    return None


class SegmentMap:
    def __init__(self, bv):
        self.bv = bv
        self.regions = []

    def add_region(self, name, segment, start):
        if name not in self.bv.sections:
            raise RuntimeError(f'unknown section {name}')
        if start != 0:
            return
        self.regions.append((name, segment))

    def effective_address(self, segment, offset):
        pass
        # for section, region_segment, region_start, region_length in self.regions:
        #     if segment != region_segment: continue
        #     if offset not in range(region_start, region_start + region_length): continue
        #     return offset - region_start + self.bv.sections[section].start
        # else:
        #     raise KeyError(f'cannot map address {segment:04}:{offset:08x}')
        # for section, region_segment, region_start, region_length in self.regions:
        #     if segment != region_segment: continue
        #     if offset not in range(region_start, region_start + region_length): continue
        #     return offset - region_start + self.bv.sections[section].start
        # else:
        #     raise KeyError(f'cannot map address {segment:04}:{offset:08x}')
