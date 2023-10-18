compile:
	cd /root/bf-sde-9.4.0/ ; sh . ../tools/./set_sde.bash
	~/tools/p4_build.sh --with-p4c=bf-p4c /home/Lessons_learned_P4/p4src/Registers_firewall.p4

run:
	pkill switchd 2> /dev/null ; cd /root/bf-sde-9.4.0/ ;./run_switchd.sh -p Registers_firewall

conf_links:
	cd /root/bf-sde-9.4.0/ ; ./run_bfshell.sh --no-status-srv -f /home/Lessons_learned_P4/ucli_cmds

control_plane:
	/root/bf-sde-9.4.0/./run_bfshell.sh --no-status-srv -i -b /home/Lessons_learned_P4/bfrt_python/control_plane_Registers_firewall.py