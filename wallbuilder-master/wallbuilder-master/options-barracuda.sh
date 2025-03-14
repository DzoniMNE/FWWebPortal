if [ "x$fwbuilder_trigger" != "xmanual" -a "x$fwbuilder_trigger" != "xcron" ]
then
    echo "options.sh: Error: \$fwbuilder_trigger must be 'manual' or 'cron'" >&2
    exit 1
fi

if [ "x$fwbuilder_run" != "xdry" -a "x$fwbuilder_run" != "xfull" ]
then
    echo "options.sh: Error: \$fwbuilder_run must be 'dry' or 'full'" >&2
    exit 1
fi

# is the whole fwbuilder process active? (1 = yes, 0 = no)
fwbuilder_active="1"

# directories
fwbuilder_base_dir="/pd/firewallbuilder"
fwbuilder_output_dir="$fwbuilder_base_dir/barracuda-output"
fwbuilder_script_dir="$fwbuilder_base_dir/tuit-barracuda-scripts"
fwbuilder_config_file="$fwbuilder_base_dir/aixboms2barracuda.yaml"

# name of the CMDB output file, e.g. tunetdb.cron.dry-run
fwbuilder_cmdb_file="$fwbuilder_output_dir/tunetdb.$fwbuilder_trigger.$fwbuilder_run-run"

# name of the firewall output file, e.g. firewall.cron.dry-run
fwbuilder_firewall_file="$fwbuilder_output_dir/firewall.$fwbuilder_trigger.$fwbuilder_run-run"

# name of the difference output file, e.g. diff.cron.dry-run
fwbuilder_diff_file="$fwbuilder_output_dir/diff.$fwbuilder_trigger.$fwbuilder_run-run"

# directories with mail infrastructure
fwbuilder_mailing_script_dir="$fwbuilder_base_dir/mailing"
fwbuilder_mailing_template_dir="$fwbuilder_base_dir/barracuda-mailing"

# temporary log files for cron runs
fwbuilder_stdout_file="/tmp/firewallbuilder.$fwbuilder_trigger.$fwbuilder_run-run.$$.stdout"
fwbuilder_stderr_file="/tmp/firewallbuilder.$fwbuilder_trigger.$fwbuilder_run-run.$$.stderr"

# mail targets (info: important information, alive: sign of life)
fwbuilder_mail_sender="Host Administrierung <hostmast@noc.tuwien.ac.at>"
fwbuilder_info_mail_target="tufw-notify@noc.tuwien.ac.at"
fwbuilder_alive_mail_target="nocadmin@noc.tuwien.ac.at"
