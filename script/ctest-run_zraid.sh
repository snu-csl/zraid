
sudo umount /dev/mapper/zraid0
sudo umount /dev/nvme3n1p1
sudo dmsetup remove /dev/mapper/zraid0
sudo rmmod zraid
sudo rmmod raizn
sudo rmmod raizn_orig

model_name="WZS4C8T1TDSP303" #ZN540
namespace_suffix="n2"

device_list=$(lsblk -o NAME,MODEL -d -n | grep "$model_name" | awk '{print "/dev/" $1}' | grep "$namespace_suffix" | sort)

device_string=$(echo $device_list | tr '\n' ' ')

cd ../src/
make CFLAGS="-DPP_INPLACE -DDEGRADE_TEST $1"
sudo insmod zraid.ko
cd -

sleep 1
sudo blkzone reset /dev/nvme0n2 
sleep 1

echo "0 15082717184 zraid 64 16 1 0 $device_string" | sudo dmsetup create zraid0

