import polars as pl
import sys
import os
import glob

def convert_json_to_parquet():
    # 1. Check if an argument was provided
    if len(sys.argv) < 2:
        print("Usage: python j2p.py <directory_or_file>")
        sys.exit(1)

    input_path = sys.argv[1]
    files = []

    # 2. Handle directory or single file
    if os.path.isdir(input_path):
        # Look for *.json in the directory
        pattern = os.path.join(input_path, "*.json")
        files = sorted(glob.glob(pattern))
        if not files:
            print(f"No .json files found in directory: {input_path}")
            sys.exit(1)
        print(f"Found {len(files)} JSON files in {input_path}")
    else:
        files = [input_path]
        print(f"Processing file: {input_path}")

    try:
        # 3. Lazy Scan
        # Passing a list of files to scan_ndjson
        q = pl.scan_ndjson(files, infer_schema_length=50000)

        print("Scanning data to determine date range (min/max timestamp)...")
        
        # 4. Determine Date Range for Filename
        # Optimization: Select only the timestamp column to avoid reading full rows
        try:
            dates = q.select([
                pl.col("timestamp").min().alias("start"),
                pl.col("timestamp").max().alias("end")
            ]).collect()
            
            start_ts = dates["start"][0]
            end_ts = dates["end"][0]
            
            # Helper to format date
            def get_date_str(ts):
                if ts is None: return "unknown"
                # If parsed as string (common in NDJSON)
                if isinstance(ts, str):
                    return ts.split("T")[0]
                # If parsed as datetime
                if hasattr(ts, "strftime"):
                    return ts.strftime("%Y-%m-%d")
                return str(ts)[:10]

            start_str = get_date_str(start_ts)
            end_str = get_date_str(end_ts)
            
            filename = f"eve_merged_{start_str}_to_{end_str}.parquet"
            
        except Exception as e:
            print(f"Warning: Could not determine dates from 'timestamp' field: {e}")
            filename = "eve_merged_unknown_dates.parquet"

        # Determine output path
        if os.path.isdir(input_path):
            output_file = os.path.join(input_path, filename)
        else:
            output_file = os.path.join(os.path.dirname(input_path) or ".", filename)

        print(f"Destination: {output_file}")
        print("-" * 30)

        # 5. Sink to Parquet
        q.sink_parquet(
            output_file, 
            compression="zstd",
            compression_level=5,
            row_group_size=100_000, 
            maintain_order=True
        )
        
        # 6. Final stats
        orig_size = sum(os.path.getsize(f) for f in files)
        orig_size_gb = orig_size / (1024**3)
        new_size_gb = os.path.getsize(output_file) / (1024**3)
        
        print(f"Success!")
        print(f"Original Size: {orig_size_gb:.2f} GB")
        print(f"Parquet Size:  {new_size_gb:.2f} GB")

    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    convert_json_to_parquet()