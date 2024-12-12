if [ "$1" == "wd" ]; then
device_list=$(lsblk -o NAME,MODEL -d -n | grep "$model_name" | awk '$1 ~ /nvme/ && $1 !~ /1$/ {print "/dev/" $1}' | sort)

for device in $device_list; do
        sudo blkzone reset $device
done
fi

if [ "$1" == "sam" ]; then
for i in $(seq 1 5); do
        sudo blkzone reset /dev/mapper/linear_${i}
        #sudo nvme zns reset /dev/nvme${i}n1
	#sudo nvme zns report-zones /dev/nvem${i}n1
done
# sudo blkzone reset /dev/nvme0n1
fi	
