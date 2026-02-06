import duckdb

parquet_file = "logs/eve_merged_2026-01-20_to_2026-01-30.parquet"
con = duckdb.connect(':memory:')
con.execute(f"CREATE VIEW logs AS SELECT * FROM read_parquet('{parquet_file}')")
print(con.execute("DESCRIBE logs").fetchall())
