printPlayerPosition = [[
	vec = game.game:GetActivePlayer():GetPos();
	posi = string.format('vec = Math:newVector(%f,%f,%f)', vec.x, vec.y, vec.z);
	printToLog("dev.log", posi);

	dir = game.game:GetActivePlayer():GetDir();
	diri = string.format('dir = Math:newVector(%f,%f,%f)', dir.x, dir.y, dir.z);
	printToLog("dev.log", diri);
]]

setVehicleData = [[
	veh = game.game:GetActivePlayer():GetOwner();
	
	veh:SetDirty(0);
	veh:SetRust(0);
	veh:SetActualFuel(100);
	veh:SetSPZText("NOMAD",true);
	color = math.random (1, 40);
	color2 = math.random (1, 40);
	veh:SetColor(color, color2);
	veh:SetMotorDamage(0);
	veh:SetDespawnImmunity(true);
]]

setVehicleFastDelay = [[
	veh = game.game:GetActivePlayer():GetOwner();
	veh:SetMotorDamage(0);
]]


setVehicleFast = [[
	veh = game.game:GetActivePlayer():GetOwner();
	veh:SetSpeed(300);
	
	setTimeout("500", setVehicleFastDelay);
]]

unbindKey("p")
unbindKey("o")
unbindKey("i")
unbindKey("l")

bindKey("p", printPlayerPosition)
bindKey("o", setVehicleData)
bindKey("i", setVehicleFast)