import base64
import time
import requests
import pandas as pd
from tqdm import tqdm
import os
from tkinter import Tk, filedialog

def select_file():
    root = Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(
        title="Select URL File",
        filetypes=[("Excel or CSV", "*.xlsx;*.xls;*.csv")]
    )
    root.destroy()
    return file_path

def b64_url(input_url):
    return base64.urlsafe_b64encode(input_url.encode()).decode().replace("=", "")

def get_vt_report(url, apikey):
    url_id = b64_url(url)
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": apikey}
    r = requests.get(vt_url, headers=headers)
    return r

def extract_info(api_data):
    d = api_data["data"]["attributes"]

    score = d["last_analysis_stats"]["malicious"]

    first_sub = d.get("first_submission_date", None)
    last_sub = d.get("last_submission_date", None)
    last_analysis = d.get("last_analysis_date", None)

    vt_link = f"https://www.virustotal.com/gui/url/{api_data['data']['id']}"

    return score, first_sub, last_sub, last_analysis, vt_link

def format_time(ts):
    if not ts:
        return ""
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))

def main():
    # Load API Keys
    keys = open("vt_keys.txt").read().splitlines()
    key_index = 0
    apikey = keys[key_index]

    # Pick file
    input_file = select_file()

    ext = os.path.splitext(input_file)[1].lower()

    if ext == ".csv":
        df = pd.read_csv(input_file)
    else:
        df = pd.read_excel(input_file)

    # Detect correct column name
    column = None
    for c in df.columns:
        if c.lower() in ["url", "urls", "link", "links"]:
            column = c
            break

    if column is None:
        print("❗ No URL column found. Please name column: url")
        return

    urls = df[column].dropna().tolist()

    output_file = "url_results.csv"
    if not os.path.exists(output_file):
        with open(output_file, "w") as f:
            f.write("URL,Score,First Submission,Last Submission,Last Analysis,VT Link\n")

    print(f"Scanning {len(urls)} URLs using VirusTotal API v3...")

    for url in tqdm(urls, desc="URLs Scanned"):
        try:
            r = get_vt_report(url, apikey)

            if r.status_code == 429:
                print("\n⚠️ API limit — switching key")
                key_index += 1
                if key_index >= len(keys):
                    print("\n❗ Out of keys — stopping")
                    break
                apikey = keys[key_index]
                r = get_vt_report(url, apikey)

            if r.status_code != 200:
                with open("failed.csv", "a") as f:
                    f.write(url + "\n")
                continue

            data = r.json()
            score, fs, ls, la, link = extract_info(data)

            fs, ls, la = format_time(fs), format_time(ls), format_time(la)

            with open(output_file, "a", encoding="utf-8") as f:
                f.write(f"{url},{score},{fs},{ls},{la},{link}\n")

        except Exception as e:
            with open("failed.csv", "a") as f:
                f.write(url + "\n")
            continue

    print("\n✔ Done")
    print(f"✔ Results saved to {output_file}")
    print("✔ Failed URLs saved to failed.csv")


if __name__ == "__main__":
    main()
