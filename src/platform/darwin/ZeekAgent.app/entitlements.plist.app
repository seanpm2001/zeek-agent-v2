<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.application-identifier</key>
		<string>org.zeek.zeek-agent.agent</string>

	<key>com.apple.security.application-groups</key>
		<array>
			<string>org.zeek.zeek-agent</string>
		</array>

	<key>com.apple.developer.system-extension.install</key>
		<true/>

	<key>com.apple.developer.endpoint-security.client</key>
      	<true/>

	<key>com.apple.developer.networking.networkextension</key>
		<array>
				<string>content-filter-provider-systemextension</string>
		</array>
</dict>
</plist>
