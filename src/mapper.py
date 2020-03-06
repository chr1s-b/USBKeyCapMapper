import pyshark

def get_usb_capture(file):
    cap = pyshark.FileCapture(file,use_json=True,include_raw=True)
    data = []
    for packet in cap:
        if 'usb' in packet:
            if int(packet.usb.transfer_type, 16) == 1:
                # cannot recover data by packet.usb.capdata
                # file issue and add to pyshark
                data.append(packet.get_raw_packet()[-8:])
    return data

defaultmap = {
2: "PostFail",
4: "a",
5: "b",
6: "c",
7: "d",
8: "e",
9: "f",
10: "g",
11: "h",
12: "i",
13: "j",
14: "k",
15: "l",
16: "m",
17: "n",
18: "o",
19: "p",
20: "q",
21: "r",
22: "s",
23: "t",
24: "u",
25: "v",
26: "w",
27: "x",
28: "y",
29: "z",
30: "1",
31: "2",
32: "3",
33: "4",
34: "5",
35: "6",
36: "7",
37: "8",
38: "9",
39: "0",
40: "Enter",
41: "esc",
42: "del",
43: "tab",
44: " ",
45: "-",
47: "[",
48: "]",
56: "/",
57: "CapsLock",
79: "RightArrow",
80: "LeftArrow"
}

def map_data(data,map_=defaultmap):
    output = ""
    for press in data:
        for byte in press:
            if byte != 0:
                if int(byte) in map_:
                    c = map_[int(byte)]
                    if c == "del":
                        output = output[:-1]
                    elif c == "PostFail":
                        continue
                    elif c == "Enter":
                        output += "\n"
                    else:
                        output += c
    return output

if __name__ == "__main__":
    capture_data = get_usb_capture("demo.pcap")
    result = map_data(capture_data)

    print(result)
