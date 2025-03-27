import tls_client
import uuid
import time
import json
import re
import base64
from fingerprint import fingerprint_1, fingerprint_2
from mods import encrypt_payload, generate_pc
import urllib.parse
class PX:
    def __init__(self, app_id: str, ft: int, collector_uri: str, host: str, sid: str, vid: str, cts: str, pxhd: str=None, proxy: str=None):
        self.session = tls_client.Session(client_identifier="chrome_127", random_tls_extension_order=True)
        if proxy != None:
            self.session.proxies = {
                'https': f'http://{proxy}',
                'http': f'http://{proxy}'
            }
        self.collector_url = collector_uri
        self.app_id = app_id
        self.vid = vid
        self.cts = cts
        self.pxhd = pxhd
        self.host = host
        self.sid = sid
        self.ft = ft
        self.session.headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': host,
            'priority': 'u=1, i',
            'sec-ch-ua': '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
        }
        self.custom_padding = list('G^S}DNK8DNa>D`K}GK77')
        self.st = int(time.time()) * 1000
        self.site_uuids = {
            "sid": sid,
            "vid": vid,
            "cts": cts
        }
        self.uuid = str(uuid.uuid4())
        self.cu = str(uuid.uuid4())
        self.pc_key = f"{self.uuid}:v8.6.6:{ft}"
        self.rsc = 3

    @staticmethod
    def parse_for_cookie(response: str) -> str:

        try:
            return response.split("316|")[1].split("|")[0]
        except:
            return None
        

    def request_1(self):
        self.raw_payload = fingerprint_1(self.host, self.uuid, self.st)
        payload_key = {
            "vid": self.site_uuids['vid'],
            "tag": "v8.6.6",
            "appID": self.app_id,
            "cu": self.cu,
            "pc": str(generate_pc(self.pc_key, self.raw_payload))
        }
        payload = {
            "payload": encrypt_payload(self.raw_payload),
            "appId": self.app_id,
            "tag": "v8.6.6",
            "uuid": self.uuid,
            "ft": self.ft,
            "seq": (self.rsc - 1),
            "en": "NTA",
            "pc": generate_pc(self.pc_key, self.raw_payload),
            "sid": self.sid,
            "rsc": self.rsc
        }
        if self.pxhd == None:
            i = 0
            for site_key in self.site_uuids:
                if self.site_uuids[site_key] != None:
                    payload[site_key] = self.site_uuids[site_key]
                i += 1
        else:
            payload['pxhd'] = self.pxhd
        self.rsc += 1
        self.resp_1 = self.session.post(self.collector_url, data=urllib.parse.urlencode(payload, safe="=")).json()['ob']
        self.resp_1 = base64.b64decode(str(self.resp_1).encode()).decode()
        return

    def solve_request(self):
        self.fp_2 = fingerprint_2(json.loads(self.raw_payload), self.resp_1, self.site_uuids)
        payload_data = {
            "payload": encrypt_payload(self.fp_2),
            "appId": self.app_id,
            "tag": "v8.6.6",
            "uuid": self.uuid,
            "ft": self.ft,
            "seq": self.rsc,
            "en": "NTA",
            "cs": f"{self.resp_1.split('1ooo11|')[1].split('~')[0]}",
            "pc": generate_pc(self.pc_key, self.fp_2),
            "sid": self.site_uuids['sid'],
            "vid": self.site_uuids['vid'],
            "cts": self.site_uuids['cts'],
            "rsc": self.rsc
        }
        if self.pxhd != None:
            payload_data['pxhd'] = self.pxhd
        self.resp_2 = self.session.post(self.collector_url, data=urllib.parse.urlencode(payload_data, safe="=")).json()['ob']
        self.resp_2 = base64.b64decode(str(self.resp_2).encode()).decode()
        input(self.resp_2)
        return
    def solve(self):
        self.request_1()
        self.solve_request()
        token = PX.parse_for_cookie(self.resp_2)
        return token

if __name__ == "__main__":
    t1 = int(time.time())
    token = PX(
        app_id="pxu6b0qd2s",
        ft=316,
        collector_uri="https://collector-pxu6b0qd2s.px-cloud.net/api/v2/collector",
        host="https://www.walmart.com/",
        sid="0396fb2e-5f0f-11ef-ae7c-f857124857d2󠄱󠄷󠄲󠄴󠄱󠄷󠄰󠄳󠄷󠄹󠄹󠄵󠄶",
        vid="0bc41189-5ec3-11ef-ba8c-eaab7bc900b7",
        cts="0c3f5439-5ec3-11ef-83dc-88da46c325fa",
       # proxy="",
       # pxhd="30f6d7ff246f451ceb1d4d5cd54297ff3d0a27d627974b5d92f23949a768da70:0bc41189-5ec3-11ef-ba8c-eaab7bc900b7"
    ).solve()
    endtime = time.time()-t1
    if token != None:
        print(f"Solved PX: {token}")
    else:
        print('Failed to solve PX')