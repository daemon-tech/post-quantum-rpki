@echo off
echo Starting Docker container...
docker compose up -d
echo Container ready. Running the full experiment inside...
docker compose exec pq bash /work/run-all.sh
echo.
echo ALL DONE! Results are in the "results" folder.
echo Commit and push to GitHub now!
pause