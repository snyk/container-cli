#!/bin/bash

set -e

GOTOOL="go tool"
COVERAGEDIR="coverage"

COVERAGEFILE="$COVERAGEDIR/coverage.out"
COVERAGEHTML=${COVERAGEFILE//.out/.html}
COVERAGETXT=${COVERAGEFILE//.out/.txt}

TOTAL_COVERAGE_THRESHOLD_FILE=coverage_threshold

CURRENT_TOTAL_COVERAGE=0
TOTAL_COVERAGE_THRESHOLD=0

init_root_dir () {
  SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
  ROOT_DIR="$(dirname "$SCRIPT_DIR")"

  cd "$ROOT_DIR" || exit
}

run_coverage_tools () {
  echo "-------------------------------------------------------------------------------"

  mkdir -p coverage && \
    # run tests with coverage and junit test reporter
    go run gotest.tools/gotestsum@latest --format standard-verbose --junitfile $COVERAGEDIR/unit-tests.xml -- -coverprofile=$COVERAGEFILE ./... && \
    # generate HTML coverage report
    $GOTOOL cover -html=$COVERAGEFILE -o $COVERAGEHTML && \
    # generate text coverage report to get the total
    $GOTOOL cover -func $COVERAGEFILE | tee $COVERAGETXT

  echo "-------------------------------------------------------------------------------"
}

get_current_total_coverage () {
  CURRENT_TOTAL_COVERAGE=$(awk 'END{print $NF}' $COVERAGETXT)
  CURRENT_TOTAL_COVERAGE="${CURRENT_TOTAL_COVERAGE//%}" # remove percentage sign
}

get_last_total_coverage () {
  if test -f "$TOTAL_COVERAGE_THRESHOLD_FILE"; then
    TOTAL_COVERAGE_THRESHOLD=$(cat $TOTAL_COVERAGE_THRESHOLD_FILE)
  else
    echo "ERROR: total coverage threshold file doesn't exist ($TOTAL_COVERAGE_THRESHOLD_FILE), please create the file with value of '0' and push it"
    exit 1
  fi
}

update_last_total_coverage () {
  echo "$CURRENT_TOTAL_COVERAGE" > $TOTAL_COVERAGE_THRESHOLD_FILE
}

# Main
echo "Set script root directory..."
init_root_dir
echo "Root directory set to: '$ROOT_DIR'"

echo "Run coverage tools..."
run_coverage_tools
echo "Finished running coverage tools successfully!"

get_current_total_coverage
echo "Extracted current total coverage [$CURRENT_TOTAL_COVERAGE]"
get_last_total_coverage
echo "Extracted coverage threshold [$TOTAL_COVERAGE_THRESHOLD]"

echo "Compare current coverage against coverage threshold..."
if (( $(echo "$TOTAL_COVERAGE_THRESHOLD > $CURRENT_TOTAL_COVERAGE" |bc -l) )); then
    echo "ERROR: current total coverage '$CURRENT_TOTAL_COVERAGE' is lower than coverage threshold '$TOTAL_COVERAGE_THRESHOLD)'"
    exit 1
fi
echo "Amazing! new coverage threshold achieved! [$CURRENT_TOTAL_COVERAGE]"

echo "Saving new coverage threshold '$CURRENT_TOTAL_COVERAGE' to file '$TOTAL_COVERAGE_THRESHOLD_FILE'..."
update_last_total_coverage
echo "Saved new coverage threshold successfully!"

exit 0