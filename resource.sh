echo "=== Shell Limits (Files & Processes) ==="
ulimit -Sn && ulimit -Hn && ulimit -Su && ulimit -Hu

echo "=== Kernel Thread & Map Limits ==="
sysctl kernel.threads-max vm.max_map_count

echo "=== Current Running Thread Counts ==="
echo "Total system threads: $(ps -eLF | wc -l)"
echo "Current user threads: $(ps -u $USER -L -o pid,tid | wc -l)"
