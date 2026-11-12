# Compatibility

[日本語](COMPATIBILITY.ja.md)

| Region | Environment | Confirmed | Remaining |
| --- | --- | --- | --- |
| JPN | New 3DS hardware | Official first-run; Wikipedia TLS 1.2; Google signed-in search; Yahoo; mobile UA; certificate display; on-console install and removal without reboot | — |
| USA | Community New 3DS XL hardware report / Azahar Plus | v0.1.0 region detection, install, Wikipedia and Yahoo.com; hardware 11.17.0-50U / Luma 13.4; UA also checked in Azahar | Hardware retest of TLS optimizations |
| KOR | Azahar Plus | Browser launch and mobile UA | TLS on hardware |
| EUR/AUS | Community EUR New 3DS XL hardware report / Azahar | v0.1.0 region detection, install, Wikipedia and Yahoo; UA also checked in Azahar | hardware retest of TLS optimizations |

The USA and EUR hardware results are community reports. Azahar checks for KOR, USA, and EUR cover launch and user agent. Use real hardware to verify TLS. [Community reports](https://www.reddit.com/r/3dshomebrew/comments/1xhlyu2/)

## Testing on hardware

On the same console and network, open Wikipedia or Yahoo.com before and after applying the patch. Record the detected region, console model, system and Luma3DS versions, browser title ID and version, URL, and any error code.
