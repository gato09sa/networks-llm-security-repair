#!/usr/bin/env bash
# tools/prepare_case.sh
# Prepara y escanea UN caso de Vul4Py (de los 100 de dataset/vul4py.csv).
# NO llama a la API de OpenAI: solo deja el caso listo y muestra su estado.
#
# Uso (desde la raíz del proyecto, con el venv activado):
#   bash tools/prepare_case.sh CVE-XXXX-YYYY
set -euo pipefail

CASE_ID="${1:?Uso: bash tools/prepare_case.sh CVE-XXXX-YYYY}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
V="$ROOT/vul4py"
LOGS="$ROOT/runs/logs"
mkdir -p "$LOGS"

# 1. El caso debe estar entre los 100 del dataset
CSV="$LOGS/case_${CASE_ID}.csv"
head -1 "$V/dataset/vul4py.csv" > "$CSV"
if ! grep -m1 "^${CASE_ID}," "$V/dataset/vul4py.csv" >> "$CSV"; then
    echo "ERROR: $CASE_ID no está en vul4py/dataset/vul4py.csv"
    exit 1
fi

# 2. Espacio libre (cada caso ocupa ~80 MB)
echo "== Disco:"; df -h / | tail -1

cd "$V"

# 3. Clonar el proyecto en workspaces/<id>/ (vulnerable/ y fixed/)
if [ -d "workspaces/$CASE_ID/vulnerable" ]; then
    echo "== $CASE_ID ya estaba preparado: se omite prepare"
else
    echo "== Preparando $CASE_ID (clona el repositorio)..."
    python scripts/prepare.py --csv "$CSV" --workspace-root workspaces --jobs 1 \
        2>&1 | tee "$LOGS/prepare_${CASE_ID}.log"
fi

# 4. Scan: comprueba que el benchmark funciona (vulnerable falla el exploit, fixed lo pasa)
echo "== Escaneando $CASE_ID (puede tardar unos minutos)..."
python scripts/vul4py.py --workspace-root workspaces scan --jobs 1 --only "$CASE_ID" \
    2>&1 | tee "$LOGS/scan_${CASE_ID}.log"

# 5. Resultado
STATUS="$(awk -F'\t' -v id="$CASE_ID" '$1 == id {print $2}' workspaces/scan_report.tsv)"
echo
echo "== Estado de $CASE_ID en scan_report.tsv: ${STATUS:-desconocido}"
if [ "$STATUS" = "OK" ]; then
    echo "Listo. Siguiente paso (UNA llamada a la API):"
    echo "  python run_experiment.py --dry-run $CASE_ID"
    echo "  python run_experiment.py $CASE_ID"
else
    echo "El caso no es utilizable: documenta este estado (no se llama a la API)."
fi
