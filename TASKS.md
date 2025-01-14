# Versa Configuration Translator - Tasks
___
## Table of Contents

- [Versa Configuration Translator - Tasks](#versa-configuration-translator---tasks)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
    - [\[F-099\] Add support for zone/interface extraction, transformation, load](#f-099-add-support-for-zoneinterface-extraction-transformation-load)
    - [\[F-103\] Sub-Element Verification Enhancement](#f-103-sub-element-verification-enhancement)
    - [\[F-104\] Decryption profile support](#f-104-decryption-profile-support)
    - [\[F-105\] Add support for Log-Settings](#f-105-add-support-for-log-settings)
    - [\[F-106\] Add support for External-list](#f-106-add-support-for-external-list)
    - [\[F-107\] Add support for Tag configurations](#f-107-add-support-for-tag-configurations)
    - [\[F-108\] Add support for Reports](#f-108-add-support-for-reports)
    - [\[F-109\] Add support for Profiles](#f-109-add-support-for-profiles)
    - [\[F-110\] Add support for SNMP Settings](#f-110-add-support-for-snmp-settings)
    - [\[F-111\] Add support for NTP Servers](#f-111-add-support-for-ntp-servers)
    - [\[F-112\] Add support for Threats](#f-112-add-support-for-threats)
    - [\[F-113\] Add support for Users](#f-113-add-support-for-users)
    - [\[F-114\] Add support for Admin Roles](#f-114-add-support-for-admin-roles)
    - [\[F-115\] Add support for Regions](#f-115-add-support-for-regions)
    - [\[F-199\] Template for TASKS.md](#f-199-template-for-tasksmd)
  - [Known Issues](#known-issues)
    - [\[I-201\] Memory Optimization for Large Configs](#i-201-memory-optimization-for-large-configs)
    - [\[I-202\] API Rate Limiting](#i-202-api-rate-limiting)
  - [Completed](#completed)
    - [\[F-101\] Flexible Service Template Naming](#f-101-flexible-service-template-naming)
    - [\[F-098\] Improve Logging](#f-098-improve-logging)
    - [\[F-102\] DOS Profile Support](#f-102-dos-profile-support)
  - [Contributing](#contributing)


___

## Features

### [F-099] Add support for zone/interface extraction, transformation, load
- **Description**: Implement complete support for zone and interface configuration translation from PAN to Versa format.
- **Priority**: High
- **Status**: In Progress
- **Owner**: RobK
- **Due Date**: 
- **Tasks:**
  - [ ] Design zone/interface data model
  - [ ] Implement zone extraction logic
  - [ ] Develop interface mapping logic
  - [ ] Create transformation rules
  - [ ] Implement loading mechanism
  - [ ] Add validation checks
  - [ ] Write unit tests
  - [ ] Document implementation

- **Dependencies:**
  - Base transformation framework
  - XML parsing infrastructure

- **References**:
  - Branch: `feature/F-099-add-zone`
  - Related Issues:
  - Related Docs: 


### [F-103] Sub-Element Verification Enhancement
- **Description**: Improve verification of configuration dependencies and relationships between elements.
  - **Priority:** High
  - **Status:** Planning  
  - **Owner:** Unassigned
  - **Due Date**: 

- **Dependency Matrix:**

| **Element** | **Sub-Elements** |
|---------|--------------|
| address_group | address |
| service_group | service |
| application | address, service, address_group |
| application_group | application |
| application_filter | application_group |
| rules | address, service, address_group, application, application_group, application_filter, zone, schedule |

- **Tasks:**
  - [ ] Implement dependency tracking
  - [ ] Add validation checks
  - [ ] Create error reporting
  - [ ] Add recovery mechanisms

- **References**:
  - Branch: `feature/F-103-SubElem-verification-enhancement`
  - Related Issues:
  - Related Docs:

### [F-104] Decryption profile support
- **Description**: Add support for decryption profile configuration migration.
  - **Priority:** High
  - **Status:** Planning  
  - **Owner:** Unassigned
  - **Due Date**: 

- **Tasks:**
  - [ ] Before uploading Decryption Policy a Default-Policy most be made.
    - https://cloud-demo.versa-networks.com/versa/ncs-services/api/config/devices/template/Deleteme_shared_device.shared_group/config/orgs/org-services/RobK/security/decryption-policies
    - {"decryption-policy-group":{"name":"Default-Policy","description":"Desc","tag":["Tag"]}}
  - [ ] Add validation checks
  - [ ] Create error reporting
  - [ ] Add recovery mechanisms

- **References**:
  - Branch: `feature/F-104-SubElem-verification-enhancement`
  - Related Issues:
  - Related Docs:

### [F-105] Add support for Log-Settings
- **Priority**: Medium
- **Status**: Planned
- **Owner**: Unassigned
- **Due Date**: TBD

**Description**:  
Develop functionality to migrate and transform PAN Log-Settings to Versa-compatible configurations.

**Tasks:**
- [ ] Analyze PAN Log-Settings structure
- [ ] Design Versa-compatible schema
- [ ] Implement extraction and transformation logic
- [ ] Add validation rules
- [ ] Test implementation
- [ ] Update documentation

---

### [F-106] Add support for External-list
- **Priority**: Medium
- **Status**: Planned
- **Owner**: Unassigned
- **Due Date**: TBD

**Description**:  
Enable migration of External-List configurations to Versa with appropriate mapping and transformation.

**Tasks:**
- [ ] Research External-List handling in PAN
- [ ] Design mapping for Versa compatibility
- [ ] Implement extraction logic
- [ ] Create transformation rules
- [ ] Add unit tests
- [ ] Document changes

---

### [F-107] Add support for Tag configurations
- **Priority**: Low
- **Status**: Planned
- **Owner**: Unassigned
- **Due Date**: TBD

**Description**:  
Add support for translating and validating Tag configurations between PAN and Versa.

**Tasks:**
- [ ] Review PAN Tag structures
- [ ] Design Versa-compatible schema
- [ ] Implement extraction and transformation logic
- [ ] Write unit tests
- [ ] Document the implementation

---

### [F-108] Add support for Reports
- **Priority**: Low
- **Status**: Planned
- **Owner**: Unassigned
- **Due Date**: TBD

**Description**:  
Introduce functionality for translating PAN report configurations into Versa-compatible formats.

**Tasks:**
- [ ] Investigate PAN report structures
- [ ] Create Versa-compatible schema
- [ ] Develop transformation rules
- [ ] Write and validate tests
- [ ] Document the changes

---

### [F-109] Add support for Profiles
- **Priority**: High
- **Status**: Planned
- **Owner**: Unassigned
- **Due Date**: TBD

**Description**:  
Develop comprehensive migration support for security and configuration profiles from PAN to Versa.

**Tasks:**
- [ ] Analyze PAN Profiles
- [ ] Design transformation and mapping
- [ ] Implement extraction module
- [ ] Add validation logic
- [ ] Test thoroughly
- [ ] Document the process

---

### [F-110] Add support for SNMP Settings
- **Priority**: Medium
- **Status**: Planned
- **Owner**: Unassigned
- **Due Date**: TBD

**Description**:  
Enable migration of SNMP settings, including communities and traps, to Versa configurations.

**Tasks:**
- [ ] Analyze SNMP settings in PAN
- [ ] Design compatible Versa schema
- [ ] Implement transformation logic
- [ ] Add tests and validations
- [ ] Document the implementation

---

### [F-111] Add support for NTP Servers
- **Priority**: Low
- **Status**: Planned
- **Owner**: Unassigned
- **Due Date**: TBD

**Description**:  
Implement migration support for NTP server configurations.

**Tasks:**
- [ ] Review NTP server configuration in PAN
- [ ] Design Versa-compatible schema
- [ ] Implement transformation rules
- [ ] Write and validate tests
- [ ] Document changes

---

### [F-112] Add support for Threats
- **Priority**: High
- **Status**: Planned
- **Owner**: Unassigned
- **Due Date**: TBD

**Description**:  
Add support for translating threat intelligence and prevention configurations to Versa.

**Tasks:**
- [ ] Analyze PAN threat configurations
- [ ] Develop Versa-compatible schema
- [ ] Implement extraction and transformation modules
- [ ] Add validation rules
- [ ] Test thoroughly
- [ ] Document the process

---

### [F-113] Add support for Users
- **Priority**: Medium
- **Status**: Planned
- **Owner**: Unassigned
- **Due Date**: TBD

**Description**:  
Introduce functionality for migrating user configurations, including roles and permissions.

**Tasks:**
- [ ] Review PAN user structures
- [ ] Design compatible Versa schema
- [ ] Implement extraction and transformation logic
- [ ] Add validation and error handling
- [ ] Test implementation
- [ ] Document changes

---

### [F-114] Add support for Admin Roles
- **Priority**: Medium
- **Status**: Planned
- **Owner**: Unassigned
- **Due Date**: TBD

**Description**:  
Support migration of admin roles, including permissions and access controls, to Versa.

**Tasks:**
- [ ] Analyze PAN admin role configurations
- [ ] Develop Versa-compatible role mappings
- [ ] Implement extraction and transformation logic
- [ ] Add validation rules
- [ ] Write unit tests
- [ ] Document changes

---

### [F-115] Add support for Regions
- **Priority**: Low
- **Status**: Planned
- **Owner**: Unassigned
- **Due Date**: TBD

**Description**:  
Introduce support for region-based configurations, including geolocation mapping.

**Tasks:**
- [ ] Investigate PAN region settings
- [ ] Design Versa-compatible schema
- [ ] Implement mapping and transformation logic
- [ ] Test thoroughly
- [ ] Document implementation

### [F-199] Template for TASKS.md
- **Description**: 
  - **Priority:** 
  - **Status:**   
  - **Owner:** Unassigned
  - **Due Date**: 

- **Tasks:**
  - [ ] 
  - [ ] 


- **References**:
  - Branch: `feature/F-199-
  - Related Issues:
  - Related Docs:

___

## Known Issues

### [I-201] Memory Optimization for Large Configs
- **Priority:** Medium  
- **Status:** Under Investigation

### [I-202] API Rate Limiting
- **Priority:** High  
- **Status:** Under Investigation

___
## Completed
### [F-101] Flexible Service Template Naming
- **Status:** Completed  
- **Completion Date:** December 15, 2024

- **Key Achievements:**
  - Implemented configurable naming patterns
  - Added support for multiple template formats
  - Created validation system for template names

### [F-098] Improve Logging
- **Description**: Implement more consistent logging messages
- **Priority**: High
- **Status**: Completed
- **Owner**: RobK
- **Due Date**: 
- **Tasks:**
  - [X] Extraction
  - [X] Deduplication
  - [X] Transformation
  - [X] Loading


- **Dependencies:**


- **References**:
  - Branch: `feature/F-098-improve-logging`
  - Related Issues:
  - Related Docs: 

### [F-102] DOS Profile Support
**Description**: Add support for DOS profile configuration migration.
  - **Priority**: Medium
  - **Status**: Planned
  - **Owner**: RobK
 - **Due Date**: 

- **Tasks:**
  - [X] Analysis of PAN DOS profile structure
  - [X] Design Versa mapping schema
  - [X] Implement extraction module
  - [X] Create transformation logic
  - [X] Add validation rules
  - [ ] Test implementation

- **References**:
  - Branch: `feature/F-102-DOS-Profile-Support`
  - Related Issues:
  - Related Docs:


___
## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

___