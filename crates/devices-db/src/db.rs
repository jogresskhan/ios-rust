//! db — embedded Apple device database (ProductType -> boards -> CPID/BDID/platform/chip).
//!
//! The JSON payload mirrors the blacktop/ipsw database format: one object keyed by
//! ProductType (e.g. "iPhone12,1"), each entry carrying a display name, a short
//! description, the SDK platform and a per-board silicon identity map. Values were
//! curated verbatim from upstream `pkg/info/data/ipsw_db.json` and cross-checked
//! against api.ipsw.me/v4 cpid/bdid at authoring time; nothing is approximated.
//!
//! Parity: see PARITY.md row `devices-db`.
//! Source: blacktop/ipsw pkg/info/data/ipsw_db.json (format + data)
//! Source: api.ipsw.me v4 /device/{id} (cpid/bdid cross-check)
//!
//! NOTE (accuracy): every board below is upstream-verified. Deviations from the
//! original task brief were resolved in favor of upstream data:
//!   - A13 CPID is 0x8030 (T8030). 0x8103 is the M1 (T8103), not the A13.
//!   - iPhone12,3 board is D421AP (not N106AP); iPhone12,5 is D431AP (not N111AP).
//!   - iPhone XR (iPhone11,8) board is N841AP; D321AP belongs to the XS (iPhone11,2).
//!   - A11 iPhones are iPhone10,x (D20AP/D21AP/D22AP/D201AP/D211AP/D221AP); A10
//!     iPhones are iPhone9,x (D10AP/D11AP/D101AP/D111AP) — the brief had swapped
//!     the ProductType generations.
//!   - platform_name follows the upstream internal H-codenames: A13 = H12P,
//!     A12 = H11P, A12X = H11G, A11 = H10P, A10 = H9P, A10X = H9G, A9 = H8P,
//!     A14 = H13P, A15 = H14P, M1 = H13G.
//!   - kc_type carries the upstream kernelcache type tag (e.g. "iphone12b"),
//!     not the "d32" shorthand suggested in the brief.
//!   - sdk_platform is the upstream `sdk` string verbatim; "deprecated" marks
//!     SDK platforms Xcode no longer ships (iPhone7,x / iPhone8,x era).
//!   - Only production "AP" boards are embedded; "DEV" engineering boards are
//!     omitted to keep the payload small.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;

/// A device keyed by ProductType, holding one [`Board`] per board config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub name: &'static str,
    pub description: &'static str,
    pub device_type: &'static str,
    pub sdk_platform: &'static str,
    pub boards: HashMap<&'static str, Board>,
}

/// Per-board silicon identity (CPID/BDID/platform/arch/kernelcache type).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Board {
    pub cpu: &'static str,
    pub cpuid: &'static str,
    pub board_id: &'static str,
    pub platform: &'static str,
    pub platform_name: &'static str,
    pub arch: &'static str,
    pub kc_type: &'static str,
}

/// Embedded database; same shape as blacktop/ipsw pkg/info/data/ipsw_db.json.
/// The string is escape-free ASCII, so serde_json borrows every field with
/// 'static lifetime (zero-copy parse into &'static str fields).
static DB_JSON: &str = r#"{
  "iPhone12,1": {
    "name": "iPhone 11",
    "description": "iPhone 11 (2019, A13 Bionic)",
    "device_type": "iPhone12,1",
    "sdk_platform": "iphoneos",
    "boards": {
      "N104AP": {
        "cpu": "A13 Bionic",
        "cpuid": "0x8030",
        "board_id": "0x04",
        "platform": "t8030",
        "platform_name": "H12P",
        "arch": "arm64e",
        "kc_type": "iphone12b"
      }
    }
  },
  "iPhone12,3": {
    "name": "iPhone 11 Pro",
    "description": "iPhone 11 Pro (2019, A13 Bionic)",
    "device_type": "iPhone12,3",
    "sdk_platform": "iphoneos",
    "boards": {
      "D421AP": {
        "cpu": "A13 Bionic",
        "cpuid": "0x8030",
        "board_id": "0x06",
        "platform": "t8030",
        "platform_name": "H12P",
        "arch": "arm64e",
        "kc_type": "iphone12"
      }
    }
  },
  "iPhone12,5": {
    "name": "iPhone 11 Pro Max",
    "description": "iPhone 11 Pro Max (2019, A13 Bionic)",
    "device_type": "iPhone12,5",
    "sdk_platform": "iphoneos",
    "boards": {
      "D431AP": {
        "cpu": "A13 Bionic",
        "cpuid": "0x8030",
        "board_id": "0x02",
        "platform": "t8030",
        "platform_name": "H12P",
        "arch": "arm64e",
        "kc_type": "iphone12"
      }
    }
  },
  "iPhone12,8": {
    "name": "iPhone SE (2nd generation)",
    "description": "iPhone SE (2nd generation) (2020, A13 Bionic)",
    "device_type": "iPhone12,8",
    "sdk_platform": "iphoneos",
    "boards": {
      "D79AP": {
        "cpu": "A13 Bionic",
        "cpuid": "0x8030",
        "board_id": "0x10",
        "platform": "t8030",
        "platform_name": "H12P",
        "arch": "arm64e",
        "kc_type": "iphone12c"
      }
    }
  },
  "iPhone11,8": {
    "name": "iPhone XR",
    "description": "iPhone XR (2018, A12 Bionic)",
    "device_type": "iPhone11,8",
    "sdk_platform": "iphoneos",
    "boards": {
      "N841AP": {
        "cpu": "A12 Bionic",
        "cpuid": "0x8020",
        "board_id": "0x0C",
        "platform": "t8020",
        "platform_name": "H11P",
        "arch": "arm64e",
        "kc_type": "iphone11b"
      }
    }
  },
  "iPhone11,2": {
    "name": "iPhone XS",
    "description": "iPhone XS (2018, A12 Bionic)",
    "device_type": "iPhone11,2",
    "sdk_platform": "iphoneos",
    "boards": {
      "D321AP": {
        "cpu": "A12 Bionic",
        "cpuid": "0x8020",
        "board_id": "0x0E",
        "platform": "t8020",
        "platform_name": "H11P",
        "arch": "arm64e",
        "kc_type": "iphone11"
      }
    }
  },
  "iPhone11,4": {
    "name": "iPhone XS Max",
    "description": "iPhone XS Max (2018, A12 Bionic)",
    "device_type": "iPhone11,4",
    "sdk_platform": "iphoneos",
    "boards": {
      "D331AP": {
        "cpu": "A12 Bionic",
        "cpuid": "0x8020",
        "board_id": "0x0A",
        "platform": "t8020",
        "platform_name": "H11P",
        "arch": "arm64e",
        "kc_type": "iphone11"
      }
    }
  },
  "iPhone11,6": {
    "name": "iPhone XS Max",
    "description": "iPhone XS Max (2018, A12 Bionic), China",
    "device_type": "iPhone11,6",
    "sdk_platform": "iphoneos",
    "boards": {
      "D331pAP": {
        "cpu": "A12 Bionic",
        "cpuid": "0x8020",
        "board_id": "0x1A",
        "platform": "t8020",
        "platform_name": "H11P",
        "arch": "arm64e",
        "kc_type": "iphone11"
      }
    }
  },
  "iPad8,1": {
    "name": "iPad Pro (11-inch)",
    "description": "iPad Pro (11-inch) (2018, A12X/A12Z Bionic)",
    "device_type": "iPad8,1",
    "sdk_platform": "iphoneos",
    "boards": {
      "J317AP": {
        "cpu": "A12X/A12Z Bionic",
        "cpuid": "0x8027",
        "board_id": "0x0C",
        "platform": "t8027",
        "platform_name": "H11G",
        "arch": "arm64e",
        "kc_type": "ipad8"
      }
    }
  },
  "iPad8,5": {
    "name": "iPad Pro (12.9-inch) (3rd generation)",
    "description": "iPad Pro (12.9-inch) (3rd generation) (2018, A12X/A12Z Bionic)",
    "device_type": "iPad8,5",
    "sdk_platform": "iphoneos",
    "boards": {
      "J320AP": {
        "cpu": "A12X/A12Z Bionic",
        "cpuid": "0x8027",
        "board_id": "0x08",
        "platform": "t8027",
        "platform_name": "H11G",
        "arch": "arm64e",
        "kc_type": "ipad8"
      }
    }
  },
  "iPad8,9": {
    "name": "iPad Pro (11-inch) (2nd generation)",
    "description": "iPad Pro (11-inch) (2nd generation) (2020, A12X/A12Z Bionic)",
    "device_type": "iPad8,9",
    "sdk_platform": "iphoneos",
    "boards": {
      "J417AP": {
        "cpu": "A12X/A12Z Bionic",
        "cpuid": "0x8027",
        "board_id": "0x3C",
        "platform": "t8027",
        "platform_name": "H11G",
        "arch": "arm64e",
        "kc_type": "ipad8b"
      }
    }
  },
  "iPhone10,1": {
    "name": "iPhone 8",
    "description": "iPhone 8 (2017, A11 Bionic)",
    "device_type": "iPhone10,1",
    "sdk_platform": "iphoneos",
    "boards": {
      "D20AP": {
        "cpu": "A11 Bionic",
        "cpuid": "0x8015",
        "board_id": "0x02",
        "platform": "t8015",
        "platform_name": "H10P",
        "arch": "arm64",
        "kc_type": "iphone10"
      }
    }
  },
  "iPhone10,2": {
    "name": "iPhone 8 Plus",
    "description": "iPhone 8 Plus (2017, A11 Bionic)",
    "device_type": "iPhone10,2",
    "sdk_platform": "iphoneos",
    "boards": {
      "D21AP": {
        "cpu": "A11 Bionic",
        "cpuid": "0x8015",
        "board_id": "0x04",
        "platform": "t8015",
        "platform_name": "H10P",
        "arch": "arm64",
        "kc_type": "iphone10"
      }
    }
  },
  "iPhone10,3": {
    "name": "iPhone X",
    "description": "iPhone X (2017, A11 Bionic)",
    "device_type": "iPhone10,3",
    "sdk_platform": "iphoneos",
    "boards": {
      "D22AP": {
        "cpu": "A11 Bionic",
        "cpuid": "0x8015",
        "board_id": "0x06",
        "platform": "t8015",
        "platform_name": "H10P",
        "arch": "arm64",
        "kc_type": "iphone10b"
      }
    }
  },
  "iPhone10,4": {
    "name": "iPhone 8",
    "description": "iPhone 8 (2017, A11 Bionic)",
    "device_type": "iPhone10,4",
    "sdk_platform": "iphoneos",
    "boards": {
      "D201AP": {
        "cpu": "A11 Bionic",
        "cpuid": "0x8015",
        "board_id": "0x0A",
        "platform": "t8015",
        "platform_name": "H10P",
        "arch": "arm64",
        "kc_type": "iphone10"
      }
    }
  },
  "iPhone10,5": {
    "name": "iPhone 8 Plus",
    "description": "iPhone 8 Plus (2017, A11 Bionic)",
    "device_type": "iPhone10,5",
    "sdk_platform": "iphoneos",
    "boards": {
      "D211AP": {
        "cpu": "A11 Bionic",
        "cpuid": "0x8015",
        "board_id": "0x0C",
        "platform": "t8015",
        "platform_name": "H10P",
        "arch": "arm64",
        "kc_type": "iphone10"
      }
    }
  },
  "iPhone10,6": {
    "name": "iPhone X",
    "description": "iPhone X (2017, A11 Bionic)",
    "device_type": "iPhone10,6",
    "sdk_platform": "iphoneos",
    "boards": {
      "D221AP": {
        "cpu": "A11 Bionic",
        "cpuid": "0x8015",
        "board_id": "0x0E",
        "platform": "t8015",
        "platform_name": "H10P",
        "arch": "arm64",
        "kc_type": "iphone10b"
      }
    }
  },
  "iPhone9,1": {
    "name": "iPhone 7",
    "description": "iPhone 7 (2016, A10 Fusion)",
    "device_type": "iPhone9,1",
    "sdk_platform": "deprecated",
    "boards": {
      "D10AP": {
        "cpu": "A10 Fusion",
        "cpuid": "0x8010",
        "board_id": "0x08",
        "platform": "t8010",
        "platform_name": "H9P",
        "arch": "arm64",
        "kc_type": "iphone9"
      }
    }
  },
  "iPhone9,2": {
    "name": "iPhone 7 Plus",
    "description": "iPhone 7 Plus (2016, A10 Fusion)",
    "device_type": "iPhone9,2",
    "sdk_platform": "deprecated",
    "boards": {
      "D11AP": {
        "cpu": "A10 Fusion",
        "cpuid": "0x8010",
        "board_id": "0x0A",
        "platform": "t8010",
        "platform_name": "H9P",
        "arch": "arm64",
        "kc_type": "iphone9"
      }
    }
  },
  "iPhone9,3": {
    "name": "iPhone 7",
    "description": "iPhone 7 (2016, A10 Fusion)",
    "device_type": "iPhone9,3",
    "sdk_platform": "deprecated",
    "boards": {
      "D101AP": {
        "cpu": "A10 Fusion",
        "cpuid": "0x8010",
        "board_id": "0x0C",
        "platform": "t8010",
        "platform_name": "H9P",
        "arch": "arm64",
        "kc_type": "iphone9"
      }
    }
  },
  "iPhone9,4": {
    "name": "iPhone 7 Plus",
    "description": "iPhone 7 Plus (2016, A10 Fusion)",
    "device_type": "iPhone9,4",
    "sdk_platform": "deprecated",
    "boards": {
      "D111AP": {
        "cpu": "A10 Fusion",
        "cpuid": "0x8010",
        "board_id": "0x0E",
        "platform": "t8010",
        "platform_name": "H9P",
        "arch": "arm64",
        "kc_type": "iphone9"
      }
    }
  },
  "iPad7,1": {
    "name": "iPad Pro (12.9-inch) (2nd generation)",
    "description": "iPad Pro (12.9-inch) (2nd generation) (2017, A10X Fusion)",
    "device_type": "iPad7,1",
    "sdk_platform": "iphoneos",
    "boards": {
      "J120AP": {
        "cpu": "A10X Fusion",
        "cpuid": "0x8011",
        "board_id": "0x0C",
        "platform": "t8011",
        "platform_name": "H9G",
        "arch": "arm64",
        "kc_type": "ipad7"
      }
    }
  },
  "iPad7,2": {
    "name": "iPad Pro (12.9-inch) (2nd generation)",
    "description": "iPad Pro (12.9-inch) (2nd generation) (2017, A10X Fusion)",
    "device_type": "iPad7,2",
    "sdk_platform": "iphoneos",
    "boards": {
      "J121AP": {
        "cpu": "A10X Fusion",
        "cpuid": "0x8011",
        "board_id": "0x0E",
        "platform": "t8011",
        "platform_name": "H9G",
        "arch": "arm64",
        "kc_type": "ipad7"
      }
    }
  },
  "iPad7,3": {
    "name": "iPad Pro (10.5-inch)",
    "description": "iPad Pro (10.5-inch) (2017, A10X Fusion)",
    "device_type": "iPad7,3",
    "sdk_platform": "iphoneos",
    "boards": {
      "J207AP": {
        "cpu": "A10X Fusion",
        "cpuid": "0x8011",
        "board_id": "0x04",
        "platform": "t8011",
        "platform_name": "H9G",
        "arch": "arm64",
        "kc_type": "ipad7"
      }
    }
  },
  "iPad7,4": {
    "name": "iPad Pro (10.5-inch)",
    "description": "iPad Pro (10.5-inch) (2017, A10X Fusion)",
    "device_type": "iPad7,4",
    "sdk_platform": "iphoneos",
    "boards": {
      "J208AP": {
        "cpu": "A10X Fusion",
        "cpuid": "0x8011",
        "board_id": "0x06",
        "platform": "t8011",
        "platform_name": "H9G",
        "arch": "arm64",
        "kc_type": "ipad7"
      }
    }
  },
  "iPad6,11": {
    "name": "iPad (5th generation)",
    "description": "iPad (5th generation) (2017, A9)",
    "device_type": "iPad6,11",
    "sdk_platform": "iphoneos",
    "boards": {
      "J71sAP": {
        "cpu": "A9",
        "cpuid": "0x8000",
        "board_id": "0x10",
        "platform": "s8000",
        "platform_name": "H8P",
        "arch": "arm64",
        "kc_type": "ipad6f"
      },
      "J71tAP": {
        "cpu": "A9",
        "cpuid": "0x8003",
        "board_id": "0x10",
        "platform": "s8003",
        "platform_name": "H8P",
        "arch": "arm64",
        "kc_type": "ipad6f"
      }
    }
  },
  "iPad6,12": {
    "name": "iPad (5th generation)",
    "description": "iPad (5th generation) (2017, A9)",
    "device_type": "iPad6,12",
    "sdk_platform": "iphoneos",
    "boards": {
      "J72sAP": {
        "cpu": "A9",
        "cpuid": "0x8000",
        "board_id": "0x12",
        "platform": "s8000",
        "platform_name": "H8P",
        "arch": "arm64",
        "kc_type": "ipad6f"
      },
      "J72tAP": {
        "cpu": "A9",
        "cpuid": "0x8003",
        "board_id": "0x12",
        "platform": "s8003",
        "platform_name": "H8P",
        "arch": "arm64",
        "kc_type": "ipad6f"
      }
    }
  },
  "iPhone8,1": {
    "name": "iPhone 6s",
    "description": "iPhone 6s (2015, A9)",
    "device_type": "iPhone8,1",
    "sdk_platform": "deprecated",
    "boards": {
      "N71AP": {
        "cpu": "A9",
        "cpuid": "0x8000",
        "board_id": "0x04",
        "platform": "s8000",
        "platform_name": "H8P",
        "arch": "arm64",
        "kc_type": "n71"
      },
      "N71mAP": {
        "cpu": "A9",
        "cpuid": "0x8003",
        "board_id": "0x04",
        "platform": "s8003",
        "platform_name": "H8P",
        "arch": "arm64",
        "kc_type": "n71"
      }
    }
  },
  "iPhone8,2": {
    "name": "iPhone 6s Plus",
    "description": "iPhone 6s Plus (2015, A9)",
    "device_type": "iPhone8,2",
    "sdk_platform": "deprecated",
    "boards": {
      "N66AP": {
        "cpu": "A9",
        "cpuid": "0x8000",
        "board_id": "0x06",
        "platform": "s8000",
        "platform_name": "H8P",
        "arch": "arm64",
        "kc_type": "n66"
      },
      "N66mAP": {
        "cpu": "A9",
        "cpuid": "0x8003",
        "board_id": "0x06",
        "platform": "s8003",
        "platform_name": "H8P",
        "arch": "arm64",
        "kc_type": "n66"
      }
    }
  },
  "iPhone8,4": {
    "name": "iPhone SE (1st generation)",
    "description": "iPhone SE (1st generation) (2016, A9)",
    "device_type": "iPhone8,4",
    "sdk_platform": "deprecated",
    "boards": {
      "N69AP": {
        "cpu": "A9",
        "cpuid": "0x8003",
        "board_id": "0x02",
        "platform": "s8003",
        "platform_name": "H8P",
        "arch": "arm64",
        "kc_type": "iphone8b"
      },
      "N69uAP": {
        "cpu": "A9",
        "cpuid": "0x8000",
        "board_id": "0x02",
        "platform": "s8000",
        "platform_name": "H8P",
        "arch": "arm64",
        "kc_type": "iphone8b"
      }
    }
  },
  "iPhone13,1": {
    "name": "iPhone 12 mini",
    "description": "iPhone 12 mini (2020, A14 Bionic)",
    "device_type": "iPhone13,1",
    "sdk_platform": "iphoneos",
    "boards": {
      "D52gAP": {
        "cpu": "A14 Bionic",
        "cpuid": "0x8101",
        "board_id": "0x0A",
        "platform": "t8101",
        "platform_name": "H13P",
        "arch": "arm64e",
        "kc_type": "iphone13"
      }
    }
  },
  "iPhone13,2": {
    "name": "iPhone 12",
    "description": "iPhone 12 (2020, A14 Bionic)",
    "device_type": "iPhone13,2",
    "sdk_platform": "iphoneos",
    "boards": {
      "D53gAP": {
        "cpu": "A14 Bionic",
        "cpuid": "0x8101",
        "board_id": "0x0C",
        "platform": "t8101",
        "platform_name": "H13P",
        "arch": "arm64e",
        "kc_type": "iphone13"
      }
    }
  },
  "iPhone13,3": {
    "name": "iPhone 12 Pro",
    "description": "iPhone 12 Pro (2020, A14 Bionic)",
    "device_type": "iPhone13,3",
    "sdk_platform": "iphoneos",
    "boards": {
      "D53pAP": {
        "cpu": "A14 Bionic",
        "cpuid": "0x8101",
        "board_id": "0x0E",
        "platform": "t8101",
        "platform_name": "H13P",
        "arch": "arm64e",
        "kc_type": "iphone13"
      }
    }
  },
  "iPhone13,4": {
    "name": "iPhone 12 Pro Max",
    "description": "iPhone 12 Pro Max (2020, A14 Bionic)",
    "device_type": "iPhone13,4",
    "sdk_platform": "iphoneos",
    "boards": {
      "D54pAP": {
        "cpu": "A14 Bionic",
        "cpuid": "0x8101",
        "board_id": "0x08",
        "platform": "t8101",
        "platform_name": "H13P",
        "arch": "arm64e",
        "kc_type": "iphone13"
      }
    }
  },
  "iPhone14,2": {
    "name": "iPhone 13 Pro",
    "description": "iPhone 13 Pro (2021, A15 Bionic)",
    "device_type": "iPhone14,2",
    "sdk_platform": "iphoneos",
    "boards": {
      "D63AP": {
        "cpu": "A15 Bionic",
        "cpuid": "0x8110",
        "board_id": "0x0C",
        "platform": "t8110",
        "platform_name": "H14P",
        "arch": "arm64e",
        "kc_type": "iphone14"
      }
    }
  },
  "iPhone14,3": {
    "name": "iPhone 13 Pro Max",
    "description": "iPhone 13 Pro Max (2021, A15 Bionic)",
    "device_type": "iPhone14,3",
    "sdk_platform": "iphoneos",
    "boards": {
      "D64AP": {
        "cpu": "A15 Bionic",
        "cpuid": "0x8110",
        "board_id": "0x0E",
        "platform": "t8110",
        "platform_name": "H14P",
        "arch": "arm64e",
        "kc_type": "iphone14"
      }
    }
  },
  "iPhone14,4": {
    "name": "iPhone 13 mini",
    "description": "iPhone 13 mini (2021, A15 Bionic)",
    "device_type": "iPhone14,4",
    "sdk_platform": "iphoneos",
    "boards": {
      "D16AP": {
        "cpu": "A15 Bionic",
        "cpuid": "0x8110",
        "board_id": "0x08",
        "platform": "t8110",
        "platform_name": "H14P",
        "arch": "arm64e",
        "kc_type": "iphone14"
      }
    }
  },
  "iPhone14,5": {
    "name": "iPhone 13",
    "description": "iPhone 13 (2021, A15 Bionic)",
    "device_type": "iPhone14,5",
    "sdk_platform": "iphoneos",
    "boards": {
      "D17AP": {
        "cpu": "A15 Bionic",
        "cpuid": "0x8110",
        "board_id": "0x0A",
        "platform": "t8110",
        "platform_name": "H14P",
        "arch": "arm64e",
        "kc_type": "iphone14"
      }
    }
  },
  "MacBookPro17,1": {
    "name": "MacBook Pro (13-inch, M1, 2020)",
    "description": "MacBook Pro (13-inch, M1, 2020) (2020, M1)",
    "device_type": "MacBookPro17,1",
    "sdk_platform": "macosx",
    "boards": {
      "J293AP": {
        "cpu": "M1",
        "cpuid": "0x8103",
        "board_id": "0x24",
        "platform": "t8103",
        "platform_name": "H13G",
        "arch": "arm64e",
        "kc_type": "mac13g"
      }
    }
  },
  "Macmini9,1": {
    "name": "Mac mini (M1, 2020)",
    "description": "Mac mini (M1, 2020) (2020, M1)",
    "device_type": "Macmini9,1",
    "sdk_platform": "macosx",
    "boards": {
      "J274AP": {
        "cpu": "M1",
        "cpuid": "0x8103",
        "board_id": "0x22",
        "platform": "t8103",
        "platform_name": "H13G",
        "arch": "arm64e",
        "kc_type": "mac13g"
      }
    }
  },
  "MacBookAir10,1": {
    "name": "MacBook Air (M1, 2020)",
    "description": "MacBook Air (M1, 2020) (2020, M1)",
    "device_type": "MacBookAir10,1",
    "sdk_platform": "macosx",
    "boards": {
      "J313AP": {
        "cpu": "M1",
        "cpuid": "0x8103",
        "board_id": "0x26",
        "platform": "t8103",
        "platform_name": "H13G",
        "arch": "arm64e",
        "kc_type": "mac13g"
      }
    }
  }
}"#;

fn parse_db() -> HashMap<&'static str, Device> {
    // A failure here is an authoring bug in this file, not a runtime condition:
    // the payload is static, escape-free and its keys match the struct fields.
    serde_json::from_str(DB_JSON).expect("devices-db: embedded ipsw_db payload failed to parse")
}

/// Process-wide database handle, parsed once on first use.
pub fn db() -> &'static HashMap<&'static str, Device> {
    static DB: OnceLock<HashMap<&'static str, Device>> = OnceLock::new();
    DB.get_or_init(parse_db)
}

/// Look up a device by ProductType, e.g. `lookup("iPhone12,1")`.
pub fn lookup(product_type: &str) -> Option<&'static Device> {
    db().get(product_type)
}

/// Reverse lookup by board config (case-insensitive), e.g. `by_board("n104ap")`.
pub fn by_board(board: &str) -> Option<(&'static str, &'static Device, &'static Board)> {
    for (product_type, device) in db().iter() {
        for (board_name, board_entry) in device.boards.iter() {
            if board_name.eq_ignore_ascii_case(board) {
                return Some((product_type, device, board_entry));
            }
        }
    }
    None
}

/// All boards with the given CPID (case-insensitive), e.g. `by_cpuid("0x8030")`
/// yields the whole A13 family. Returns (ProductType, board config, board)
/// triples, sorted by ProductType for deterministic output.
pub fn by_cpuid(cpuid: &str) -> Vec<(&'static str, &'static str, &'static Board)> {
    let mut hits = Vec::new();
    for (product_type, device) in db().iter() {
        for (board_name, board) in device.boards.iter() {
            if board.cpuid.eq_ignore_ascii_case(cpuid) {
                hits.push((*product_type, *board_name, board));
            }
        }
    }
    hits.sort_unstable_by_key(|(pt, _, _)| *pt);
    hits
}

/// All boards on the given platform (case-insensitive), e.g. `by_platform("t8030")`.
/// Returns (ProductType, board config, board) triples, sorted by ProductType.
pub fn by_platform(platform: &str) -> Vec<(&'static str, &'static str, &'static Board)> {
    let mut hits = Vec::new();
    for (product_type, device) in db().iter() {
        for (board_name, board) in device.boards.iter() {
            if board.platform.eq_ignore_ascii_case(platform) {
                hits.push((*product_type, *board_name, board));
            }
        }
    }
    hits.sort_unstable_by_key(|(pt, _, _)| *pt);
    hits
}

/// The A13/T8030 device family — the core target of this emulator stack:
/// iPhone 11, iPhone 11 Pro, iPhone 11 Pro Max and iPhone SE (2nd generation).
/// Returns (ProductType, device, board) triples, sorted by ProductType.
pub fn t8030_devices() -> Vec<(&'static str, &'static Device, &'static Board)> {
    let mut hits = Vec::new();
    for (product_type, device) in db().iter() {
        for board in device.boards.values() {
            if board.platform.eq_ignore_ascii_case("t8030") {
                hits.push((*product_type, device, board));
            }
        }
    }
    hits.sort_unstable_by_key(|(pt, _, _)| *pt);
    hits
}

/// Re-export the database as pretty-printed JSON (same shape as the embedded payload).
pub fn export_json() -> String {
    serde_json::to_string_pretty(db()).expect("devices-db: serializing the in-memory db cannot fail")
}
