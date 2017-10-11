#!/usr/bin/python3
import argparse
import random
from concurrent.futures import ThreadPoolExecutor

import requests
import json
import re
import xmltodict
from haversine import haversine
import oauth2 as oauth

from flask import Flask, render_template, jsonify, request, session
from werkzeug.utils import redirect

app = Flask(__name__)

consumer = oauth.Consumer(key = 'oFhymc8HqwdalBS6iNOTVEb7l8j5I30u7QtUjLzc', secret = 'gmwTHR912fGp6Z7wZTPH3t7f01WzRf9gqI79X3QV')
DEFAULT_SECRET_KEY = "s8359ewflw#9wd"
osm_xml_tags = {'way': 'way', 'node': 'node', 'tag': 'tag', 'nd': 'nd'}
OFFSET = 0.0005
re_desc = re.compile(".*#(\d+)")
changeset_template = """<osm>
  <changeset>
    <tag k="comment" v="Fixing unconnected paths"/>
  </changeset>
</osm>"""


def random_bbox():
    bbox = [[-125, -60], [30, 50]]
    left = random.randint(0, (bbox[0][1] - bbox[0][0]) / 5) * 5 + bbox[0][0]
    bottom = random.randint(0, (bbox[1][1] - bbox[1][0]) / 5) * 5 + bbox[1][0]
    return {'left': left, 'right': left + 5, 'bottom': bottom, 'top': bottom + 5}


@app.route('/')
def index():
    return redirect(request.path + "index.html", 302)


@app.route('/index.html')
def index_html():
    return render_template('index.html')


@app.route('/land.html')
def oauth_token_landing_page():
    return render_template('land.html')


@app.route('/fetch_data')
def roulette(sample_size=100):
    for i in range(0, 10):
        bbox = random_bbox()
        uri = 'https://www.keepright.at/export.php?format=geojson&ch=0,50&left={left}&right={right}&bottom={bottom}&top={top}'.format(**bbox)
        response = requests.get(uri)
        print("%s %s [%d] %s" % (response.request.method, response.url, response.status_code,
                                 response.text if response.status_code != 200 else ""))
        candidates = response.json()['features']
        print("Found {} features".format(len(candidates)))
        if len(candidates) > 0:
            if len(candidates) > sample_size:
                candidates = random.sample(candidates, sample_size)
            return jsonify({'boundingbox': {'type': 'Polygon',
                                            'coordinates': [[[bbox['left'], bbox['bottom']],
                                                             [bbox['left'], bbox['top']],
                                                             [bbox['right'], bbox['top']],
                                                             [bbox['right'], bbox['bottom']],
                                                             [bbox['left'], bbox['bottom']]]]},
                            'features': candidates
                            })
    return jsonify({})


def process_feature(feature):
    geometry = feature['geometry']
    properties = feature['properties']
    node_id = properties['object_id']
    way_id = parse_way_id(properties['description'])

    suggested_fix = fetch_current_state_from_osm(geometry['coordinates'], node_id, way_id, properties['schema'], properties['error_id'])
    return {
        'node_id': node_id,
        'way_id': way_id,
        'node': feature,
        'suggested_fix': suggested_fix
    }


@app.route('/prepare_data', methods=['POST'])
def prepare_data():
    sample = request.json
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(process_feature, sample)

    seen = set()
    filtered = []
    for result in results:
        if 'deduplication_info' in result['suggested_fix']:
            dedup = result['suggested_fix']['deduplication_info']
            if dedup in seen:
                continue
            seen.add(dedup)
        filtered.append(result)
    return jsonify(sorted(filtered, key=lambda e: e['suggested_fix'].get('order', 0), reverse=True))


@app.route('/quickfix', methods=['POST'])
def quickfix():
    client = oauth.Client(consumer, oauth.Token(request.json.get('oauth_token'), request.json.get('oauth_token_secret')))

    fix = request.json['payload']
    if fix['type'] == 'replace_node':
        reponse, content = client.request("https://api.openstreetmap.org/api/0.6/way/{}".format(fix['way_id']), 'GET')
        if reponse.status == 200:
            doc = xmltodict.parse(content, force_list=osm_xml_tags)
            way = doc['osm']['way'][0]
            if fix['way_version_expected'] != way['@version']:
                return jsonify({'status': 'already_fixed'})

            for nd in way.get('nd', []):
                if nd['@ref'] == fix['current_node_id']:
                    changeset_id = None
                    if 'changeset' in session:
                        changeset_id = session['changeset']
                        response, content = client.request('https://api.openstreetmap.org/api/0.6/changeset/' + changeset_id, 'GET')
                        if response.status != 200 or xmltodict.parse(content)['osm']['changeset']['@open'] != 'true':
                            changeset_id = None

                    if not changeset_id:
                        response, content = client.request('https://api.openstreetmap.org/api/0.6/changeset/create', 'PUT', changeset_template.encode())
                        if response.status == 200:
                            changeset_id = content.decode()
                            session['changeset'] = changeset_id
                        else:
                            return jsonify({'status': 'failed', 'reason': 'Unable to create changeset: ' + content.decode()})
                    # update way id
                    nd['@ref'] = fix['new_node_id']

                    # update version and changeset
                    way['@changeset'] = changeset_id
                    del way['@user']
                    del way['@uid']
                    del way['@timestamp']
                    way_update_request = xmltodict.unparse(doc)
                    response, content = client.request("https://api.openstreetmap.org/api/0.6/way/{}".format(fix['way_id']), 'PUT', way_update_request.encode())
                    #print("%s, %s %d %s" % (response.request.method, response.url, response.status, response.text))

                    response, content = client.request("https://api.openstreetmap.org/api/0.6/node/{}".format(fix['current_node_id']), 'GET')
                    if response.status == 200:
                        node_delete_request = re.sub('changeset="\d+"', 'changeset="%s"' % changeset_id, content.decode())
                        response, content = client.request("https://api.openstreetmap.org/api/0.6/node/{}".format(fix['current_node_id']), 'DELETE', node_delete_request.encode())
                        #print("%s, %s %d %s" % (response.request.method, response.url, response.status, response.text))


                    # finally, mark as fixed in keepright.at database
                    response = requests.post("https://www.keepright.at/comment.php?st=ignore_t&co=Fixed+with+osm-stitch+in+changeset+{}&schema={}&id={}".format(changeset_id, fix['schema_id'], fix['error_id']))
                    print("%s %s [%d] %s" % (response.request.method, response.url, response.status_code, response.text if response.status_code != 200 else ""))
                    return jsonify({'status':'success', 'changeset': changeset_id})
        return jsonify({'status': 'failed', 'reason': 'unknown fix type'})


def find_by_tag(way, tag_key):
    tag = find(way['tag'], lambda tag: tag and tag['@k'] == tag_key)
    if tag:
        return tag.get('@v')
    return None

def find_by_id(doc, element_id):
    return find(doc, lambda d: d['@id'] == element_id)


def find(doc, expression):
    if not doc:
        return None
    if isinstance(doc, dict):
        return doc if expression(doc) else None
    else:
        return next((n for n in doc if expression(n)), None)


def to_point(node):
    return float(node['@lat']), float(node['@lon'])


def geojson_linestring(p0, p1):
    return {'type': 'Feature',
            'geometry': {
                'type': 'LineString',
                'coordinates': [(p0[1], p0[0]), (p1[1], p1[0])]}}


def find_way_with_node(doc, node_id):
    for way in doc['way']:
        for nd in way['nd']:
            if nd['@ref'] == node_id:
                return way
    return None


def calculate_order(way0, way1, distance):
    order = 1000 - distance
    for way in [way0, way1]:
        if find_by_tag(way, 'highway') in ['path', 'track']:
            order += 1000
    return order


def fetch_current_state_from_osm(point, node_id, way_id, schema_id, error_id):
    map_response = requests.get("http://api.openstreetmap.org/api/0.6/map.json?bbox={left},{bottom},{right},{top}".format(left=point[0] - OFFSET, bottom=point[1] - OFFSET, right=point[0] + OFFSET, top=point[1] + OFFSET))
    if map_response.status_code == 200:
        doc = xmltodict.parse(map_response.text, force_list=osm_xml_tags)['osm']
        node = find_by_id(doc.get('node'), node_id)
        way = find_by_id(doc.get('way'), way_id)

        if node and way:
            # check if we can suggest a solution by finding a close node on the close way
            # check first if the close way is a highway
            if find_by_tag(way, 'highway'):
                min_distance = 50
                closest_ref = None
                p0 = to_point(node)
                for nd in way['nd']:
                    ref_node = find_by_id(doc.get('node'), nd['@ref'])
                    distance = haversine(p0, to_point(ref_node)) * 1000
                    if distance < min_distance:
                        min_distance = distance
                        closest_ref = ref_node
                if closest_ref:
                    way_of_node = find_way_with_node(doc, node_id)
                    if way_of_node:
                        geometry = None
                        if min_distance > 1:
                            # find precessor of node to draw linestring
                            if len(way_of_node['nd']) > 1:
                                if way_of_node['nd'][0]['@ref'] == node_id:
                                    pt = find_by_id(doc.get('node'), way_of_node['nd'][1]['@ref'])
                                    geometry = geojson_linestring(to_point(pt), to_point(closest_ref))
                                elif way_of_node['nd'][-1]['@ref'] == node_id:
                                    pt = find_by_id(doc.get('node'), way_of_node['nd'][-2]['@ref'])
                                    geometry = geojson_linestring(to_point(pt), to_point(closest_ref))
                        return {'geometry': geometry,
                                'order': calculate_order(way, way_of_node, min_distance),
                                'payload': {
                                    'type': 'replace_node',
                                    'schema_id': schema_id,
                                    'error_id': error_id,
                                    'way_id': way_of_node['@id'],
                                    'way_version_expected': way_of_node['@version'],
                                    'current_node_id': node_id,
                                    'new_node_id':  closest_ref['@id']},
                                'deduplication_info':  "{}/{}".format(*sorted([node_id, closest_ref['@id']]))
                                }
    else:
        print(map_response.text)
    return {}


def parse_way_id(description):
    result = re_desc.search(description)
    return result.group(1)

# for the standalone runner
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('--verbose', dest='verbose', required=False, action='store_true', help='verbose progress output')
    parser.add_argument('--port', dest='port', default=5000, type=int, help='port number')
    parser.add_argument('--secret-key', dest='secret', default=DEFAULT_SECRET_KEY, help='cookie secret')
    args = parser.parse_args()

    app.secret_key = args.secret
    app.run(threaded=True, host="0.0.0.0", port=args.port, debug=True)
else:
    app.secret_key = DEFAULT_SECRET_KEY
