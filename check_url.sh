#!/usr/bin/env bash
echo -e "\e[32m⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿"
echo -e "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿"
echo -e "⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠃⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿"
echo -e "⣿⣿⣿⣿⡿⠿⠛⢉⣀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿"
echo -e "⣿⣿⠟⢁⣤⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿"
echo -e "⣿⠃⣰⣿\e[41m\e[37m ANTIPHISHING SETTINGS \e[0m\e[32m⣿⣿⣿"
echo -e "⣿⠀⢿⣿⣿⣿⣿⣿⡏⠀⢠⣾⣿⣿⡆⠀⠸⣿⣿⣿⣿⣿⡿⣿⣿⣿⣿⣿⣿⣿"
echo -e "⣿⣧⠈⠻⣿⣿⣿⣿⣷⠾⠻⣿⣿⣿⠇⠀⢰⣿⣿⣿⣿⣿⣷⠀⠙⢿⣿⣿⣿⣿"
echo -e "⣿⣿⣿⣦⣄⣈⣉⣀⣤⣴⡞⠋⠉⠁⠀⠠⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠻⣿⣿⣿"
echo -e "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣦⠀⠀⠘⣿⣿⣿⣿⣿⣿⡇⠀⡀⠀⠹⣿⣿"
echo -e "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡀⠀⠈⢿⣿⣿⣿⣿⣧⣾⣿⡄⠀⢹⣿"
echo -e "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠈⢿⣿⣿⣿⣿⣿⣿⠇⠀⢸⣿"
echo -e "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠻⢿⣿⣿⡿⠋⠀⠀⣼⣿"
echo -e "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⢀⣼⣿⣿"
echo -e "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣤⣤⣶⣾⣿⣿⣿⣿\e[0m"

TEMP_FILE="phishing.lst.tmp"
> "$TEMP_FILE"

TOTAL=$(wc -l < phishing.lst)
COUNT=0

while read -r encoded; do
  [ -z "$encoded" ] && continue
  
  ((COUNT++))
  url=$(echo "$encoded" | base64 --decode)
  
  printf "\r\033[K[%d/%d] Checking: %s" "$COUNT" "$TOTAL" "$url"
  
  HTTP_STATUS=$(curl -m 5 -L -o /dev/null -s -w "%{http_code}" "$url")
  
  if [ "$HTTP_STATUS" -eq 200 ]; then
    echo "$encoded" >> "$TEMP_FILE"
  fi
done < phishing.lst

echo -e "\nDone!"

mv "$TEMP_FILE" phishing.lst
