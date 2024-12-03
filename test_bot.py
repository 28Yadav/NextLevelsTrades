import asyncio
from bot import TradingBot
from utils import log_info, log_error  # Assuming these are in the utils module

async def main():
    # Define your API keys, assets, trade size, and indicator
    api_key = 'aYEtQLO511DTwuTbUmTEllYGqZSfJjxkzh7r3Zz3yrBMtjPUK73FVmvKKqZoAJSfARdx6bWgoHic4H7X1kbtVw'  # Replace with your actual API key
    secret = 'qWd5tr3oX5M78seEeAgjPf0sAwqcpzMErxcmKp1lcAHwJQUDP8QYRaVjwSZgSM7slao4vakoVleeZhAVZbg'  # Replace with your actual secret key
    assets = ['XRP/USDT', 'BTC/USDT']  # Assets you want to test with real trades
    trade_size_usdt = 30  # Real trade size in USDT, adjust as needed
    indicator = 'ma'  # Moving Average (or 'stochastic', 'macd', depending on what you want to test)
    exchange = 'bingx'  # Your exchange

    # Initialize the TradingBot with the desired assets and trade size
    bot = TradingBot(api_key, secret, assets, trade_size_usdt, indicator, exchange)

    # Modify Take Profit (TP) and Stop Loss (SL) percentages for instant testing
    bot.take_profit_percentage = 0.0001  # 0.01% take profit for instant trigger
    bot.stop_loss_percentage = 0.0001  # 0.01% stop loss for instant trigger

    # Start a real trade (e.g., on XRP/USDT)
    log_info("Placing a real trade for testing TP/SL with XRP/USDT...")

    # Example: Manually force a long position for XRP/USDT
    entry_price = await bot.execute_position('XRP/USDT:USDT', 'buy')  # Test with a long trade

    if entry_price:
        log_info(f"Long position entered at {entry_price} USDT for XRP/USDT")

        # Simulate tight TP/SL immediately after the trade is placed
        bot.trade_states['XRP/USDT:USDT']["entry_price"] = entry_price
        bot.trade_states['XRP/USDT:USDT']["trade_started"] = True
        bot.trade_states['XRP/USDT:USDT']["position_type"] = 'long'

        # Now monitor for TP/SL
        log_info("Monitoring for Take Profit or Stop Loss...")

        # Keep checking the TP/SL function in a loop until TP or SL is hit
        try:
            while bot.trade_states['XRP/USDT:USDT']["trade_started"]:
                state = bot.trade_states['XRP/USDT:USDT']

                if state["trade_started"]:
                    log_info(f"Checking TP/SL for XRP/USDT...")
                    status = await bot.check_stop_loss_take_profit('XRP/USDT:USDT')

                    if status == 'exit':
                        log_info(f"TP/SL hit for XRP/USDT. Exiting trade.")
                        state["trade_started"] = False  # Stop further monitoring after exiting
                        state["position_type"] = None
                        state["entry_price"] = None
                        break
                else:
                    log_info(f"No active trade for XRP/USDT. Exiting monitor loop.")
                    break

                # Sleep for a short time before checking again
                await asyncio.sleep(1)  # Check every 1 second for quick response

        except KeyboardInterrupt:
            log_info("Test interrupted manually. Exiting.")
    else:
        log_error("Failed to enter trade.")

if __name__ == '__main__':
    asyncio.run(main())
