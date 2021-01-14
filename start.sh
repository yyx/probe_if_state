netns=$(readlink -f /proc/1/ns/net|awk -F "[" '{print $2}'|awk -F "]" '{print $1}')
nohup ./probe_if_state $netns &>>probe_if_state.log &
