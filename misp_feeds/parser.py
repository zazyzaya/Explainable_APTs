from collections import defaultdict
import glob 
import json 

from tqdm import tqdm 

reports = glob.glob('**/*.json')

ta_map = dict()
with open('threat-actor.json', 'r') as f:
    tas = json.loads(f.read())

# Build out list of synonyms
for ta in tas['values']:
    k = ta['value'].upper()
    aliases = ta.get('meta', dict()).get('synonyms', [])

    for ta_name in aliases + [k]:
        ta_map[ta_name.upper()] = k


dirs = set() 
observed = defaultdict(lambda : 0)
for fname in tqdm(reports):
    dir = fname.split('/')[0]
    with open(fname,'r') as f:
        db = json.loads(f.read())

    has_apt = False 
    k = None 
    for tag in db['Event'].get('Tag', []): 
        name = tag['name']
        if 'threat-actor' in name:
            has_apt = True
            k = name.replace(
                'misp-galaxy:threat-actor=', ''
            ).replace('"', '').upper() 

            if k in ta_map: 
                observed[ta_map[k]] += 1
                break 

    # No names in db found
    else:
        if has_apt:
            print(k, 'not found in db')
            observed[k] += 1 


tots = [(k,v) for k,v in observed.items()]
tots.sort(key=lambda x : x[1])
cnt = 0
for k,v in tots:
    print(k,v)
    cnt += v 
print("="*10,"\nTotal:",cnt)
print(dirs)