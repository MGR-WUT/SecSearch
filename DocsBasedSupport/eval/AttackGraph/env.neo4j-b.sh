# Source in a dedicated terminal for Experiment B (does not change settings.yaml).
#   source eval/AttackGraph/env.neo4j-b.sh
#
# Requires: docker compose up -d neo4j_b  (Bolt 7688, Browser http://localhost:7475)

export NEO4J_URI=bolt://localhost:7688
export NEO4J_USERNAME=neo4j
export NEO4J_PASSWORD=neo4j_password
export NEO4J_DATABASE=neo4j

export B_RUN=eval/AttackGraph/runs/kev-gpt-oss-20b-cloud
export B_MODEL=gpt-oss:20b-cloud
export B_INGESTION=gpt-oss-20b-cloud
