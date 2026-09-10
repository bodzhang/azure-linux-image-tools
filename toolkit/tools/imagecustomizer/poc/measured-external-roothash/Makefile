.PHONY: check

check:
	sh -n build-azlinux-vhd.sh externalize-azlinux-vhd.sh collect.sh verify.sh
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_addon_cmdline.py test_verify.py test_vhd_info.py
