if target_machine.system() != 'windows'
	wireshark = dependency('wireshark', required: true)
	subdir('n5305a')
else
	message('Building the Wireshark dissector on Windows requires extra steps. See the `BUILDING_ON_WINDOWS.md` file in the `src/dissectors/wireshark` directory')
endif
