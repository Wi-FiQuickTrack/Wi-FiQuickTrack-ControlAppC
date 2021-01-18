#!/bin/bash

# Local variable
file="/etc/NetworkManager/NetworkManager.conf"
bkup_file="/etc/NetworkManager/NetworkManager.conf.bkup"
debug=0
i=0
array=()
main_section=0
keyfile_section=0

# Error return
error_exit() {
  echo "$1Please manually add the unmanaged-interface:wl* to ${file} and restart NetworkManager if Network Manager is enabled."
  exit 0
}

# Backup file
backup() {
  if [ -f "$file" ]; then
    cp -rf "$file" "$bkup_file"
  fi
}

# Restore file from backup
restore() {
  if [ -f "$bkup_file" ]; then
    cp -rf "$bkup_file" "$file"
  fi
}

# Read lines from configuration
read_config() {
  # Return error if NetworkManager.conf doesn't exist
  if [ ! -f "${file}" ]; then
    error_exit "The patch script cannot find ${file}. "
  fi
  # Read to array
  # echo "Read lines from ${file}."
  while IFS= read -r line;
    do array+=("$line");
  done < "$file"
  # echo "Read lines completes. Total line number is ${#array[@]}."
}

# Save lines to configuration
save_config() {
  printf "%s\n" "${array[@]}" >${file}
}

# Parse and update main section
patch_main() {
  # Update [main] to include plugin=*,keyfile*
  echo "Patching main section."
  for (( i=0; i< ${#array[@]}; i++ ));
  do
    line="${array[$i]}"
    # Skip comment
    if [[ "$line" =~ \#.* ]]; then
      # echo "skip $line"
      continue
    fi
    # Start to check plugin after main section 
    if [[ "$line" == "[main]" ]]; then
      main_section=1
      continue
    fi
    if [[ "$main_section" = "0" ]]; then
      continue
    fi
 
    # Find plugins
    if [[ "$line" =~ plugins=.*keyfile.* ]]; then
      echo "$line Found keyfile from plugins. Don't require to patch main section."
      break
    elif [[ "$line" =~ plugins=.* ]]; then
      echo "$line Found plugins but no keyfile. Append keyfile to plugin."
      array[$i]="$line,keyfile"
      break
    fi
    # Append plugins
    if [[ "$line" =~ \[.* ]]; then
      echo "End of main section. Unable to find plugins in main ${i}, append \"plugins=keyfile\"."
      array=( "${array[@]:0:$i}" "plugins=keyfile" "${array[@]:$i}")
      break
    fi
  done

  # Debug
  if [[ "${debug}" = 1 ]]; then
    echo "Debug main section..."
    for line in "${array[@]}"; do 
      echo "(DEBUG) $line"
    done
    echo ""
  fi

  if [[ "$main_section" = 0 ]]; then
    error_exit "Unable to find the main section. "
  fi
}

# Parse and update keyfile section
patch_keyfile() {
  # Update [keyfile] to include unmanaged-devices=interface-name:wl*
  echo "Patching keyfile section."
  for (( i=0; i< ${#array[@]}; i++ ));
  do
    line="${array[$i]}"
    # Skip comment
    if [[ "$line" =~ \#.* ]]; then
      # echo "skip $line"
      continue
    fi
    # Start to check unmanaged-devices after keyfile section 
    if [[ "$line" == "[keyfile]" ]]; then
      keyfile_section=1
      continue
    fi
    if [[ "$keyfile_section" = "0" ]]; then
      continue
    fi
    # Find unmanaged-devices
    if [[ "$line" =~ unmanaged-devices=.*wl.* ]]; then
      echo "$line Found unmanaged-devices --> $line"
      break
    elif [[ "$line" =~ unmanaged-devices=.* ]]; then
      echo "$line Found unmanaged-devices but no wl*. Replace the configuration."
      array[$i]="unmanaged-devices=interface-name:wl*"
      break
    fi
    # Append unmanaged-devices to keyfile section if not existed
    if [[ "$line" =~ \[.* ]]; then
      echo "End of keyfile section. Unable to find unmanaged-devices in keyfile ${i}. Append \"unmanaged-devices=interface-name:wl*\""
      array=( "${array[@]:0:$i}" "unmanaged-devices=interface-name:wl*" "${array[@]:$i}")
      break
    fi
  done
  # Append keyfile and unmanaged-devices if not existed
  if [[ "$keyfile_section" = "0" ]]; then
    echo "Unable to find keyfile section. Append the section."
    array+=( "" "[keyfile]" "unmanaged-devices=interface-name:wl*")
  fi

  # Debug
  if [[ "${debug}" = 1 ]]; then
    echo "Debug keyfile section..."
    for line in "${array[@]}"; do 
      echo "(DEBUG) $line"
    done
    echo ""
  fi
}

if [[ "$1" = "restore" ]]; then
  echo "Restore ${file} from ${bkup_file}"
  restore
  systemctl restart NetworkManager
else
  echo "Start to patch ${file}"
  backup
  read_config
  patch_main
  patch_keyfile
  save_config
  echo "The original configuration is backup to ${bkup_file}. You can restore it if any problem."
  echo "sudo cp -rf ${bkup_file} ${file}"
  echo "sudo systemctl restart NetworkManager"
  systemctl stop wpa_supplicant
  systemctl restart NetworkManager
  echo "Patch complete"
fi
exit 0
