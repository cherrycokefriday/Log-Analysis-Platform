"""
/opt/spark/bin/pyspark \
  --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.1 \
  --conf spark.jars.ivy=/tmp/.ivy
#
"""

from pyspark.sql import SparkSession
from pyspark.sql.functions import col, from_json, lit
from pyspark.sql.types import StructType, StructField, StringType, IntegerType, BooleanType

from pyspark.sql.functions import to_json, struct, lower, when, window, count
from pyspark.sql.functions import to_timestamp



allowed_locations = ["USA", "Germany", "Netherlands", "India", "Singapore", "Egypt"]

spark = SparkSession.builder \
    .appName("KafkaPassthroughTest") \
    .getOrCreate()


# LOGIN

input_df = spark.readStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "kafka:29092") \
    .option("subscribe", "login_logs") \
    .option("startingOffsets", "latest") \
    .option("failOnDataLoss", "false") \
    .load()

schema = StructType([
    StructField("EventCode", StringType()),
    StructField("timestamp", StringType()),
    StructField("event_type", StringType()),
    StructField("ComputerName", StringType()),
    StructField("src_ip", StringType()),
    StructField("geo", StringType()),
    StructField("success", BooleanType()),
    StructField("LogonType", StringType())
])

# Convert Kafka value (bytes) → JSON
login_df = input_df.selectExpr("CAST(value AS STRING) as json_str") \
    .select(from_json(col("json_str"), schema).alias("data")) \
    .select("data.*")



## FILTERING 
geo_violations = login_df.filter(
    ~col("geo").isin(allowed_locations)
).select(
    col("src_ip"),
    col("timestamp"),
    col("geo"),
    lit("geo_violation").alias("alert_type"),
    lit("high").alias("severity")
)

# back to kafka
geo_alerts = geo_violations.select(
    to_json(struct("*")).alias("value")
)

login_df = login_df.withColumn(
    "event_time",
    to_timestamp(col("timestamp"))
)

# Brute force detection
failed_logins = login_df.filter(col("success") == False)


#brute_event = failed_logins.withColumn("rdp_time", to_timestamp("rdp_time"))


# Add watermark BEFORE window aggregation
bruteforce = failed_logins \
    .withWatermark("event_time", "5 minutes") \
    .groupBy(
        col("src_ip"),
        window(col("event_time"), "2 minutes", "30 seconds")
    ).agg(
        count("*").alias("failed_count")
    ).filter(
        col("failed_count") >= 5
    ).select(
        col("src_ip"),
        col("window.start").alias("start_time"),
        col("window.end").alias("end_time"),
        col("failed_count"),
        lit("bruteforce_attempt").alias("alert_type"),
        lit("critical").alias("severity")
    )

bruteforce_out = bruteforce.select(
    to_json(struct("*")).alias("value")
)


geoQuery = geo_alerts.writeStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "kafka:29092") \
    .option("topic", "geo_login") \
    .option("checkpointLocation", "/tmp/kafka_passthrough_geocheckpoint") \
    .outputMode("append") \
    .start()


loginsQuery = bruteforce_out.writeStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "kafka:29092") \
    .option("topic", "proc_login") \
    .option("checkpointLocation", "/tmp/kafka_passthrough_logincheckpoint") \
    .outputMode("append") \
    .start()



# PROCESS
rules = [
    {
        "parent": "winword.exe",
        "child_contains": "powershell",
        "severity": "high",
        "mitre": "T1059.001 - PowerShell (Possible phishing macro execution)"
    },
    {
        "parent": "excel.exe",
        "child_contains": "cmd",
        "severity": "high",
        "mitre": "T1059.003 - Command Shell (Macro execution)"
    },
    {
        "parent": "chrome.exe",
        "child_contains": "psexec",
        "severity": "critical",
        "mitre": "T1569.002 - Service Execution (Possible lateral movement)"
    },
    {
        "parent": "explorer.exe",
        "child_contains": "temp",
        "severity": "high",
        "mitre": "T1036 - Masquerading (Execution from Temp directory)"
    }
]

input_df = spark.readStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "kafka:29092") \
    .option("subscribe", "process_creation_logs") \
    .option("startingOffsets", "latest") \
    .option("failOnDataLoss", "false") \
    .load()

schema = StructType([
    StructField("EventCode", StringType()),
    StructField("timestamp", StringType()),
    StructField("event_type", StringType()),
    StructField("ComputerName", StringType()),
    StructField("NewProcessName", StringType()),
    StructField("ProcessCreator", StringType()),
    StructField("ProcessCommandLine", StringType())
])

# Convert Kafka value (bytes) → JSON
process_df = input_df.selectExpr("CAST(value AS STRING) as json_str") \
    .select(from_json(col("json_str"), schema).alias("data")) \
    .select("data.*")

# Initialize columns BEFORE loop
malproc = process_df \
    .withColumn("severity", lit("low")) \
    .withColumn("mitre_technique", lit(None))

for rule in rules:
    condition = (
        (lower(col("ProcessCreator")) == rule["parent"].lower()) #&
        #(lower(col("NewProcessName")).contains(rule["child_contains"].lower()))
    )
    malproc = malproc.withColumn(
        "severity",
        when(condition, rule["severity"]).otherwise(col("severity"))
    ).withColumn(
        "mitre_technique",
        when(condition, rule["mitre"]).otherwise(col("mitre_technique"))
    )

proc_alerts = malproc.filter(col("severity") != "low")

proc_alerts_out = proc_alerts.select(
    to_json(struct("*")).alias("value")
)


procQuery = proc_alerts_out.writeStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "kafka:29092") \
    .option("topic", "proc_exec") \
    .option("checkpointLocation", "/tmp/kafka_passthrough_proccheckpoint") \
    .outputMode("append") \
    .start()


# PRIVILEGE

input_df = spark.readStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "kafka:29092") \
    .option("subscribe", "process_creation_logs") \
    .option("startingOffsets", "latest") \
    .option("failOnDataLoss", "false") \
    .load()

schema = StructType([
    StructField("EventCode", StringType()),
    StructField("timestamp", StringType()),
    StructField("event_type", StringType()),
    StructField("ComputerName", StringType()),
    StructField("AccountName", StringType()),
    StructField("Privilege", StringType())
])

# Convert Kafka value (bytes) → JSON
privilege_df = input_df.selectExpr("CAST(value AS STRING) as json_str") \
    .select(from_json(col("json_str"), schema).alias("data")) \
    .select("data.*")


priv_events = privilege_df.select(
    col("ComputerName"),
    col("timestamp").alias("priv_time")
)

# merge with rdp logons
rdp_logons = login_df.filter(
    (col("EventCode") == "4624") &
    (col("LogonType") == "10")
).select(
    col("src_ip"),
    col("timestamp").alias("rdp_time"),
    col("ComputerName")
)



rdp_logons = rdp_logons.withColumn("rdp_time", to_timestamp("rdp_time"))
priv_events = priv_events.withColumn("priv_time", to_timestamp("priv_time"))

from pyspark.sql.functions import expr


alerts = rdp_logons.join(
    priv_events,
    on="ComputerName"
).where(
    expr("""
        priv_time >= rdp_time AND
        priv_time <= rdp_time + interval 10 minutes
    """)
)

rdp_priv_event = alerts.selectExpr(
    "ComputerName",
    "rdp_time",
    "priv_time",
    "'rdp_privilege_correlation' as alert_type",
    "'high' as severity",
    "'T1078' as mitre_technique"
)


rdp_df = rdp_priv_event.select(
    to_json(struct("*")).alias("value")
)


rdpQuery = rdp_df.writeStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "kafka:29092") \
    .option("topic", "rdp_priv") \
    .option("checkpointLocation", "/tmp/kafka_passthrough_rdpcheckpoints") \
    .outputMode("append") \
    .start()

loginsQuery.awaitTermination()

geoQuery.awaitTermination()

procQuery.awaitTermination()

rdpQuery.awaitTermination()