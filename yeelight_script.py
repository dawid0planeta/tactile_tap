import time
from yeelight import Bulb

bulb = Bulb("192.168.50.67")
bulb.turn_on()
wait = True
min_temp = 1700
current_temp = min_temp
step = 86
max_temp = 6500
i = 1


while (current_temp <= max_temp):
    print(f"i: {i}, temp: {current_temp}, response: {bulb.set_color_temp(current_temp, effect="smooth", duration=30)}")
    # step = min(round(step * 1.03), max_temp - current_temp)
    step = get_step(i)
    i += 1
    current_temp = current_temp + step
    time.sleep(0.5)



temp_dict = {
    0: 0,
    1: 1700,
    2: 1800,
    60: 6500
}