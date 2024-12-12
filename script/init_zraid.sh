sudo umount /dev/mapper/zraid0
sudo dmsetup remove /dev/mapper/zraid0
sudo rmmod zraid

cd ../nvme/
./make.sh
./insmod.sh
cd -

sleep 3


scheduler="none"
#scheduler="mq-deadline"
if [ "$1" == "wd" ]; then
for i in {0..5}; do
    echo $scheduler | sudo tee /sys/block/nvme${i}n2/queue/scheduler
done
fi
if [ "$1" == "sam" ]; then
echo $scheduler | sudo tee /sys/block/nvme1n1/queue/scheduler
fi

