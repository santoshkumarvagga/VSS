start /b wmic product where "name = 'Vmware Tools'" call Uninstall
echo "sleeping for 10"
sleep 10
