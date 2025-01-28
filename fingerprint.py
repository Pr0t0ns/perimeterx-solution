import random
import json
import time
import pytz
from datetime import datetime
import urllib.parse
from mods import fn, generate_pc
def fingerprint_1(host: str, uuid: str, st: int):
    return json.dumps([
    {
        "t": "PX12095",
        "d": {
            "PX11645": host,
            "PX12207": 0,
            "PX12458": "Win32",
            "PX11902": 0,
            "PX11560": random.randint(2809, 3809),
            "PX12248": 3600,
            "PX11385": st,
            "PX12280": st + random.randint(1, 30),
            "PX11496": uuid,
            "PX12564": None,
            "PX12565": -1,
            "PX11379": False
        }
    }
], separators=(",", ":"))

def generate_js_heap_sizes() -> dict:
    jsHeapSizeLimit = 4294705152
    totalJSHeapSize = random.randint(58000000, 60000000)
    usedJSHeapSize = random.randint(int(0.90 * totalJSHeapSize), int(0.99 * totalJSHeapSize))
    return {
        "jsHeapSizeLimit": jsHeapSizeLimit,
        "totalJSHeapSize": totalJSHeapSize,
        "usedJSHeapSize": usedJSHeapSize
    }

def fingerprint_2(payload_1: dict, response_1: str, site_keys: dict) -> str:
    heap_sizes = (generate_js_heap_sizes())
    payload_1 = payload_1[0]['d']
    payload_1['PX11840'] = f"{datetime.now(pytz.timezone('America/Los_Angeles')).strftime('%a %b %d %Y %H:%M:%S GMT%z')} (Pacific Daylight Time)"
    payload_1['PX12118'] = response_1.split("11o1o1|")[1].split("~")[0]
    payload_1['PX11701'] = response_1.split("1o111o|")[1].split("~")[0]
    payload_1['PX11431'] = response_1.split("o11o11o1|")[1].split("~")[0]
    payload_1['PX12454'] = response_1.split("o11o11oo|")[1].split("~")[0]
    payload_1['PX11555'] = heap_sizes['jsHeapSizeLimit']
    return json.dumps([
    {
        "t": "PX11590",
        "d": {
            "PX11431": int(payload_1['PX11431']),
            "PX11804": f"{generate_pc('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36', payload_1['PX11496'], False)}",
            "PX12118": payload_1['PX12118'],
            "PX11746": f"{generate_pc('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36', site_keys['vid'], False)}", # good
            "PX11371": f"{generate_pc('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36', site_keys['sid'], False)}", # good
            "PX11529": heap_sizes['usedJSHeapSize'], 
            "PX11555": payload_1['PX11555'], 
            "PX11833": heap_sizes['totalJSHeapSize'], 
            "PX11840": payload_1['PX11840'],
            "PX11526": False,
            "PX11684": False,
            "PX11812": False,
            "PX12335": True,
            "PX12080": 10,
            "PX11678": True,
            "PX11349": "visible",
            "PX12397": False,
            "PX11387": 0,
            "PX12150": 1280,
            "PX12304": False,
            "PX11651": 752, # good
            "PX11867": "missing",
            "PX12254": False,
            "PX11540": True,
            "PX11548": False,
            "PX11446": True,
            "PX12550": 1,
            "PX12431": 0,
            "PX11991": 24,
            "PX11837": 0,
            "PX11632": 0,
            "PX11409": 1,
            "PX12597": 1,
            "PX11508": "49e5084e",
            "PX11452": "7c5f9724",
            "PX12218": "65d826e0",
            "PX12481": "a9269e00",
            "PX11780": "50a5ec55",
            "PX11701": payload_1['PX11701'],
            fn(payload_1['PX11701'], int(payload_1['PX11431']) % 10 + 2): fn(payload_1['PX11701'], int(payload_1['PX11431']) % 10 + 1),
            "PX12454": int(payload_1['PX12454']),
            "PX12330": "109|66|66|70|80", # good
            "PX11705": 1690, # good
            "PX11938": True,
            "PX11602": True,
            "PX12021": "false",
            "PX12421": "false",
            "PX12124": 1,
            "PX11609": 1,
            "PX12291": "",
            "PX11881": [
                "loadTimes",
                "csi",
                "app"
            ],
            "PX12207": payload_1['PX12207'],
            "PX11538": 2,
            "PX11984": "TypeError: Cannot read properties of null (reading '0')\n    at $n (https://arcteryx.com/943r4Fb8/init.js:2:20544)\n    at Tl (https://arcteryx.com/943r4Fb8/init.js:3:83090)\n    at Nl (https://arcteryx.com/943r4Fb8/init.js:3:94232)\n    at https://arcteryx.com/943r4Fb8/init.js:3:82534\n    at nrWrapper (<anonymous>:1:23349)",
            "PX11645": payload_1['PX11645'],
            "PX11597": [],
            "PX12023": "",
            "PX11337": False,
            "PX12588": "webkit",
            "PX12551": "https:",
            "PX12552": "function share() { [native code] }",
            "PX12553": "America/Los_Angeles",
            "PX12567": "w3c",
            "PX12576": "screen",
            "PX12555": {
                "plugext": {
                    "0": {
                        "f": "internal-pdf-viewer",
                        "n": "PDF Viewer"
                    },
                    "1": {
                        "f": "internal-pdf-viewer",
                        "n": "Chrome PDF Viewer"
                    },
                    "2": {
                        "f": "internal-pdf-viewer",
                        "n": "Chromium PDF Viewer"
                    },
                    "3": {
                        "f": "internal-pdf-viewer",
                        "n": "Microsoft Edge PDF Viewer"
                    },
                    "4": {
                        "f": "internal-pdf-viewer",
                        "n": "WebKit built-in PDF"
                    }
                },
                "plugins_len": 5
            },
            "PX12583": {
                "smd": {
                    "ok": True,
                    "ex": False
                }
            },
            "PX12578": {},
            "PX12594": False,
            "PX12566": False,
            "PX12571": "60921215", # good
            "PX12579": {
                "support": True,
                "status": {
                    "effectiveType": "4g",
                    "rtt": 50,
                    "downlink": 10,
                    "saveData": False
                }
            },
            "PX12581": "default",
            "PX12582": 3, # good
            "PX12587": False,
            "PX12278": True,
            "PX11694": False,
            "PX12294": False,
            "PX12514": True,
            "PX12515": "TypeError: Cannot read properties of undefined (reading 'width')",
            "PX12516": "webkit",
            "PX12517": 33, # good
            "PX12518": False,
            "PX12545": False,
            "PX12593": False,
            "PX12595": "AudioData.SVGAnimatedAngle.SVGMetadataElement.appEventData.appEventDataProcess",
            "PX12544": True,
            "PX12589": "succeeded", # good
            "PX11524": True,
            "PX11843": 1280,
            "PX11781": 800,
            "PX12121": 1280,
            "PX12128": 752, # good
            "PX12387": "1280X800",
            "PX12003": 24,
            "PX11380": 24,
            "PX11494": 244, # good
            "PX12411": 665, # good
            "PX12443": 0,
            "PX12447": 0,
            "PX11533": True,
            "PX12079": False,
            "PX12069": [
                "PDF Viewer",
                "Chrome PDF Viewer",
                "Chromium PDF Viewer",
                "Microsoft Edge PDF Viewer",
                "WebKit built-in PDF"
            ],
            "PX12286": 5, # good
            "PX11576": True,
            "PX12318": True,
            "PX11384": True,
            "PX11886": True,
            "PX11583": "en-US",
            "PX12458": payload_1['PX12458'],
            "PX11681": [
                "en-US"
            ],
            "PX11754": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
            "PX12037": True,
            "PX11390": 420, # good
            "PX11621": 8,
            "PX11657": 1,
            "PX12081": "Gecko",
            "PX11908": "20030107",
            "PX12314": "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
            "PX11829": True,
            "PX11464": True,
            "PX12054": 2,
            "PX11821": "Netscape",
            "PX11479": "Mozilla",
            "PX11674": True,
            "PX12241": random.choice([50, 100]),
            "PX11372": False,
            "PX11683": 10,
            "PX11561": "4g",
            "PX11877": True,
            "PX12100": True,
            "PX12506": "x86",
            "PX12507": "64",
            "PX12508": [
                {
                    "brand": "Not)A;Brand",
                    "version": "99"
                },
                {
                    "brand": "Google Chrome",
                    "version": "127"
                },
                {
                    "brand": "Chromium",
                    "version": "127"
                }
            ],
            "PX12509": False,
            "PX12510": "",
            "PX12511": "Windows",
            "PX12512": "15.0.0",
            "PX12513": "127.0.6533.100",
            "PX12548": True,
            "PX12549": True,
            "PX11685": 8,
            "PX12573": "b7bc2747",
            "PX11539": "64556c77",
            "PX11528": "",
            "PX12271": "10207b2f",
            "PX11849": "10207b2f",
            "PX12464": "90e65465",
            "PX11356": True,
            "PX12426": True,
            "PX11791": True,
            "PX11517": True,
            "PX12520": True,
            "PX12524": "4YC14YCd4YCd4YCV4YCe4YCX4YGS5J256aus7r266YaI5oCR7r27", # good
            "PX12527": "d4acbe702b2ce9d7b185cbf0062c8dea", #good
            "PX12486": None,
            "PX12260": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
            "PX12249": False,
            "PX11897": "90e65465",
            "PX11303": False,
            "PX11515": False,
            "PX12133": False,
            "PX12340": False,
            "PX11738": False,
            "PX11723": False,
            "PX11389": False,
            "PX11839": False,
            "PX11460": False,
            "PX12102": False,
            "PX11378": False,
            "PX12317": False,
            "PX12169": 2,
            "PX11902": 1,
            "PX11560": payload_1['PX11560'],
            "PX11332": int(time.time()) * 1000,
            "PX12248": 3600,
            "PX11385": payload_1['PX11385'],
            "PX12280": payload_1['PX12280'],
            "PX11496": payload_1['PX11496'],
            "PX12564": payload_1['PX12564'],
            "PX12565": payload_1['PX12565'],
            "PX11379": payload_1['PX11379']
        }
    },
    {
        "t": "PX11547",
        "d": {
            "PX12492": "c505c10e26a1b7a7741437db9f82916b", 
            "PX12570": "c62afe6a00ff19ebce9e4c9d36ec18c0",
            "PX11352": "a1c3b153658dad38c14af23e061b7827",
            "PX12292": "WebKit",
            "PX11811": [],
            "PX11567": "WebKit WebGL",
            "PX12032": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
            "PX11536": [
                "ANGLE_instanced_arrays",
                "EXT_blend_minmax",
                "EXT_clip_control",
                "EXT_color_buffer_half_float",
                "EXT_depth_clamp",
                "EXT_disjoint_timer_query",
                "EXT_float_blend",
                "EXT_frag_depth",
                "EXT_polygon_offset_clamp",
                "EXT_shader_texture_lod",
                "EXT_texture_compression_bptc",
                "EXT_texture_compression_rgtc",
                "EXT_texture_filter_anisotropic",
                "EXT_texture_mirror_clamp_to_edge",
                "EXT_sRGB",
                "KHR_parallel_shader_compile",
                "OES_element_index_uint",
                "OES_fbo_render_mipmap",
                "OES_standard_derivatives",
                "OES_texture_float",
                "OES_texture_float_linear",
                "OES_texture_half_float",
                "OES_texture_half_float_linear",
                "OES_vertex_array_object",
                "WEBGL_blend_func_extended",
                "WEBGL_color_buffer_float",
                "WEBGL_compressed_texture_s3tc",
                "WEBGL_compressed_texture_s3tc_srgb",
                "WEBGL_debug_renderer_info",
                "WEBGL_debug_shaders",
                "WEBGL_depth_texture",
                "WEBGL_draw_buffers",
                "WEBGL_lose_context",
                "WEBGL_multi_draw",
                "WEBGL_polygon_mode"
            ],
            "PX12149": [
                "[1, 1]",
                "[1, 1024]",
                8,
                "yes",
                8,
                24,
                8,
                16,
                32,
                16384,
                1024,
                16384,
                16,
                16384,
                30,
                16,
                16,
                4096,
                "[32767, 32767]",
                "no_fp",
                23,
                127,
                127,
                23,
                127,
                127,
                23,
                127,
                127,
                23,
                127,
                127,
                23,
                127,
                127,
                23,
                127,
                127,
                23,
                127,
                127,
                23,
                127,
                127,
                23,
                127,
                127,
                23,
                127,
                127,
                23,
                127,
                127,
                23,
                127,
                127
            ],
            "PX12352": "Google Inc. (Intel)",
            "PX11455": "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x00009A49) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "PX11534": "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)",
            "PX12503": "96ff435b6ebac2817a4d5bfc475aa8e4",
            "PX12502": "dab81cb438e9b1ecd9151a3ba33a82b8",
            "PX11927": "3ce3010a7aa84b5452916c2a0d27895d",
            "PX12572": "d443f5504fa6a5697a42485877388608",
            "PX11477": "126.86972438948578",
            "PX12109": "2dce8c55c6897067fdf0c76ddf6e6d50",
            "PX12362": "3d7309e340ce622c7cc645a0fb998ad7",
            "PX12354": "926ed8ba7284400652ca3b397cda2f6a",
            "PX12491": "7523bf6e5dcadcffdae6b3063827e345",
            "PX12622": "016beb17dd57a6e446b36265284c0c9c",
            "PX12130": [
                "__nr_require",
                "_satellite",
                "__satelliteLoaded",
                "_dataLayerOverwriteMonitor",
                "_etmc",
                "_etmc_temp",
                "_hjSettings",
                "_fbq",
                "ueto_d9f9acb3f8",
                "Native2JSBridge",
                "_jelly_sdks",
                "_scPxHelper",
                "_scPxTeller",
                "$"
            ],
            "PX12351": [
                "__reactEvents$9yebrlving5",
                "__reactEvents$2xqoe4gotbg",
                "destination_publishing_iframe_amersports_0_name"
            ],
            "PX11386": [
                "webdriver"
            ],
            "PX12275": [
                "data-react-helmet"
            ],
            "PX12525": "9a1f14dbcec17f462191c2f67265e6d9",
            "PX12526": "d41d8cd98f00b204e9800998ecf8427e",
            "PX11948": 2,
            "PX11986": True,
            "PX12299": True,
            "PX12331": False,
            "PX11316": False,
            "PX11448": True,
            "PX12196": "missing",
            "PX12427": [
                "__nr_require",
                "_satellite",
                "__satelliteLoaded",
                "_dataLayerOverwriteMonitor",
                "_etmc",
                "_pxAppId",
                "_943r4Fb8handler",
                "_etmc_temp",
                "_hjSettings",
                "_fbq",
                "__core-js_shared__",
                "_jelly_sdks",
                "_scPxHelper",
                "_scPxTeller",
                "$"
            ],
            "PX11842": [
                "__reactEvents$9yebrlving5",
                "__reactEvents$2xqoe4gotbg"
            ],
            "PX12439": [
                "PDF Viewer::Portable Document Format::application/pdf~pdf::text/pdf~pdf",
                "Chrome PDF Viewer::Portable Document Format::application/pdf~pdf::text/pdf~pdf",
                "Chromium PDF Viewer::Portable Document Format::application/pdf~pdf::text/pdf~pdf",
                "Microsoft Edge PDF Viewer::Portable Document Format::application/pdf~pdf::text/pdf~pdf",
                "WebKit built-in PDF::Portable Document Format::application/pdf~pdf::text/pdf~pdf"
            ],
            "PX11993": "1724127507125",
            "PX12228": "TypeError: Cannot read properties of null (reading '0') at $n (https://arcteryx.com/943r4Fb8/init.js:2:20544) at func (https://arcteryx.com/943r4Fb8/init.js:3:113581) at Pt (https://arcteryx.com/943r4Fb8/init.js:2:15161) at https://arcteryx.com/943r4Fb8/init.js:3:115268 at nrWrapper (<anonymous>:1:23349)",
            "PX12288": True,
            "PX12446": 33,
            "PX12236": "fd7149bbfb316699ef918fa7bb7510a8",
            "PX11309": "d41d8cd98f00b204e9800998ecf8427e",
            "PX11551": "fd7149bbfb316699ef918fa7bb7510a8",
            "PX12586": 2,
            "PX11843": 1280,
            "PX11781": 800,
            "PX12121": 1280,
            "PX12387": "1280X800",
            "PX11380": 24,
            "PX12003": 24,
            "PX12128": 752,
            "PX11849": "10207b2f",
            "PX11583": "en-US",
            "PX12458": payload_1['PX12458'],
            "PX11754": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
            "PX11681": [
                "en-US"
            ],
            "PX12037": True,
            "PX11621": 8,
            "PX11685": 8,
            "PX11390": 420,
            "PX11678": True,
            "PX11840": payload_1['PX11840'],
            "PX11540": True,
            "PX11539": "64556c77",
            "PX11555": payload_1['PX11555'],
            "PX11452": "7c5f9724",
            "PX12527": "d4acbe702b2ce9d7b185cbf0062c8dea",
            "PX12486": None,
            "PX12501": "9c123657e0cb01aa902df81c9a781488",
            "PX11902": 2,
            "PX11560": payload_1['PX11560'],
            "PX12280": payload_1['PX12280'],
            "PX11496": payload_1['PX11496'],
            "PX12564": payload_1['PX12564'],
            "PX12565": payload_1['PX12565'],
            "PX11379": payload_1['PX11379']
        }
    }
], separators=(",", ":")).replace(r"\n", "\\n").replace(r")\n", r")\\n").replace(r"r\n", r"r\\n").replace(r"Error\n", r"Error\\n")