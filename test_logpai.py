import os
import urllib.request
from src.universal_parser import UniversalLogParser

LOGPAI_URLS = {
    "HDFS": "https://raw.githubusercontent.com/logpai/loghub/master/HDFS/HDFS_2k.log",
    "BGL": "https://raw.githubusercontent.com/logpai/loghub/master/BGL/BGL_2k.log",
    "Apache": "https://raw.githubusercontent.com/logpai/loghub/master/Apache/Apache_2k.log",
    "Linux": "https://raw.githubusercontent.com/logpai/loghub/master/Linux/Linux_2k.log"
}

os.makedirs("data/logpai", exist_ok=True)

for name, url in LOGPAI_URLS.items():
    filepath = f"data/logpai/{name}_2k.log"
    print(f"\n{'='*50}\nTesting {name} LogPAI Dataset\n{'='*50}")
    
    # Download if not exists
    if not os.path.exists(filepath):
        print(f"Downloading {name}_2k.log...")
        try:
            urllib.request.urlretrieve(url, filepath)
        except Exception as e:
            print(f"Failed to download {name}: {e}")
            continue

    # Parse using UniversalLogParser
    parser = UniversalLogParser()
    print(f"Parsing {filepath}...")
    
    # We will just iterate through to let it collect stats
    records = list(parser._parse_iter(filepath))
    
    stats = parser.stats
    accuracy = (stats['parsed_lines'] / stats['total_lines']) * 100 if stats['total_lines'] > 0 else 0
    
    print("\n--- Parsing Statistics ---")
    print(f"Total Lines:      {stats['total_lines']}")
    print(f"Successfully Parsed: {stats['parsed_lines']}")
    print(f"Failed/Fallback:  {stats['failed_lines']}")
    print(f"Accuracy:         {accuracy:.2f}%")
    print(f"Detected Format:  {', '.join(stats['formats_used'])}")
    
    if records and len(records) > 0:
        print("\nSample Parsed Record:")
        print(records[0])
