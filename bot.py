import time
import pandas as pd
import logging
import ccxt
import asyncio
from utils import log_info, log_error

class TradingBot:
    def __init__(self, api_key, secret, assets, trade_size_usdt, indicator, exchange):
        self.api_key = api_key
        self.secret = secret

        if isinstance(assets, str):
            self.assets = [self._format_asset_name(asset.strip()) for asset in assets.split(",")]
        elif isinstance(assets, list):
            self.assets = [self._format_asset_name(asset.strip()) for asset in assets]
        else:
            raise ValueError("Assets must be either a string or a list of asset names.")

        self.trade_size_usdt = trade_size_usdt
        self.indicator = indicator
        self.exchange = exchange.lower()
        self.trade_states = {asset: {"trade_started": False, "position_type": None, "entry_price": None} for asset in self.assets}
        self.stop_loss_percentage = 0.03
        self.take_profit_percentage = 0.03
        self.trade_started = True
        self.ccxt_exchange = self._initialize_exchange()

        if self.trade_size_usdt < 30:
            raise ValueError("Trade size must be at least 30 USDT.")

        self._validate_assets()

    def _format_asset_name(self, asset):
        if not asset.endswith(':USDT'):
            return f"{asset}:USDT"
        return asset

    def _initialize_exchange(self):
        exchange_class = getattr(ccxt, self.exchange)
        exchange = exchange_class({
            'apiKey': self.api_key,
            'secret': self.secret,
            'enableRateLimit': True,
            'options': {'defaultType': 'future'}
        })
        return exchange

    def _validate_assets(self):
        try:
            self.ccxt_exchange.load_markets()
            for asset in self.assets:
                if asset not in self.ccxt_exchange.markets:
                    raise ValueError(f"Invalid asset: {asset}. Please check your asset configuration.")
        except Exception as e:
            raise ValueError(f"Error loading markets or validating asset {self.assets}: {str(e)}")

    async def _fetch_ticker_price(self, asset_name):
        try:
            ticker = self.ccxt_exchange.fetch_ticker(asset_name)
            return float(ticker['last'])
        except Exception as e:
            log_error(f"Error fetching ticker price for {asset_name}: {str(e)}")
            return None

    async def fetch_historical_prices(self, asset_name, limit):
        try:
            ohlcv = self.ccxt_exchange.fetch_ohlcv(asset_name, timeframe='15m', limit=limit)
            df = pd.DataFrame(ohlcv, columns=['timestamp', 'open', 'high', 'low', 'close', 'volume'])
            df['timestamp'] = pd.to_datetime(df['timestamp'], unit='ms')
            df.set_index('timestamp', inplace=True)
            return df
        except Exception as e:
            log_error(f"Error fetching historical prices for {asset_name}: {str(e)}")
            return pd.DataFrame()

    async def execute_position(self, asset_name, side):
        try:
            market_price = self.ccxt_exchange.fetch_ticker(asset_name)['last']
            contract_size = self.trade_size_usdt / market_price
            self.ccxt_exchange.create_order(
                symbol=asset_name,
                type='market',
                side=side,
                amount=contract_size
            )
            if side == 'buy':
                print("Open Long")
            else:
                print("Open Short")
            return market_price
        except Exception as e:
            log_error(f"Error occurred during entering {side} position for {asset_name}: {str(e)}")
            return None

    async def exit_position(self, asset_name, position_type):
        try:
            market_price = self.ccxt_exchange.fetch_ticker(asset_name)['last']
            contract_size = self.trade_size_usdt / market_price

            if position_type in ['long', 'short']:
                side = 'sell' if position_type == 'long' else 'buy'

                order = self.ccxt_exchange.create_order(
                    symbol=asset_name,
                    type='market',
                    side=side,
                    amount=contract_size,
                    params={'reduceOnly': True}  # Ensure it's a closing order
                )

                log_info(f"Exited {position_type} position for {asset_name} futures at {market_price} USDT.")
                log_info(f"Order details: {order}")
                
                return market_price
            else:
                log_error(f"Invalid position type {position_type} for {asset_name}")
                return None
        except Exception as e:
            log_error(f"Error occurred during exiting position for {asset_name}: {str(e)}")
            return None

    async def check_stop_loss_take_profit(self, asset_name):
        try:
            state = self.trade_states[asset_name]
            current_price = await self._fetch_ticker_price(asset_name)

            if state["position_type"] == 'long':
                if current_price >= state["entry_price"] * (1 + self.take_profit_percentage):
                    print(f"Take profit reached for {asset_name}. Closing long position.")
                    await self.exit_position(asset_name, 'long')
                    return 'exit'
                elif current_price <= state["entry_price"] * (1 - self.stop_loss_percentage):
                    print(f"Stop loss reached for {asset_name}. Closing long position.")
                    await self.exit_position(asset_name, 'long')
                    return 'exit'
            elif state["position_type"] == 'short':
                if current_price <= state["entry_price"] * (1 - self.take_profit_percentage):
                    print(f"Take profit reached for {asset_name}. Closing short position.")
                    await self.exit_position(asset_name, 'short')
                    return 'exit'
                elif current_price >= state["entry_price"] * (1 + self.stop_loss_percentage):
                    print(f"Stop loss reached for {asset_name}. Closing short position.")
                    await self.exit_position(asset_name, 'short')
                    return 'exit'
            return 'hold'
        except Exception as e:
            log_error(f"Error during stop-loss/take-profit check for {asset_name}: {str(e)}")
            return 'error'

    async def check_active_trade(self, asset_name):
        try:
            positions = self.ccxt_exchange.fetch_positions(symbols=[asset_name])
            for position in positions:
                if position['contracts'] > 0:
                    return True
            return False
        except Exception as e:
            log_error(f"Error occurred while checking active trade for {asset_name}: {str(e)}")
            return False

    async def start_trading(self):
        try:
            while self.trade_started:
                for asset_name in self.assets:
                    try:
                        state = self.trade_states[asset_name]
                        active_trade = await self.check_active_trade(asset_name)

                        if active_trade:
                            print(f"Active trade on {asset_name}")
                            state["trade_started"] = True
                            status = await self.check_stop_loss_take_profit(asset_name)
                            if status == 'exit':
                                state["trade_started"] = False
                                state["position_type"] = None
                                state["entry_price"] = None
                        else:
                            print(f"No active trade on {asset_name}")
                            state["trade_started"] = False

                        df = await self.fetch_historical_prices(asset_name, 100)
                        if df.empty:
                            continue

                        if self.indicator == 'ma':
                            df = self.calculate_ma(df)
                            signal = self.generate_ma_signal(df)
                        elif self.indicator == 'stochastic':
                            df = self.calculate_stochastic(df)
                            signal = self.generate_stochastic_signal(df)
                        elif self.indicator == 'macd':
                            df = self.calculate_macd(df)
                            signal = self.generate_macd_signal(df)
                        elif self.indicator == 'atr':
                            df = self.calculate_atr(df)
                            signal = self.generate_atr_signal(df)
                        elif self.indicator == 'vwap':
                            df = self.calculate_vwap(df)
                            signal = self.generate_vwap_signal(df)
                        elif self.indicator == 'fibonacci':
                            levels = self.calculate_fibonacci(df)
                            signal = self.generate_fibonacci_signal(df, levels)
                        elif self.indicator == 'rsi':
                            df = self.calculate_rsi(df)
                            signal = self.generate_rsi_signal(df)
                        elif self.indicator == 'bollinger':
                            df = self.calculate_bollinger_bands(df)
                            signal = self.generate_bollinger_signal(df)
                        else:
                            signal = 'hold'

                        if signal == 'long' and not state["trade_started"]:
                            state["entry_price"] = await self.execute_position(asset_name, 'buy')
                            if state["entry_price"]:
                                state["trade_started"] = True
                                state["position_type"] = 'long'
                        elif signal == 'short' and not state["trade_started"]:
                            state["entry_price"] = await self.execute_position(asset_name, 'sell')
                            if state["entry_price"]:
                                state["trade_started"] = True
                                state["position_type"] = 'short'
                        elif signal == 'hold':
                            print(f"on hold for {asset_name}")
                    except Exception as e:
                        log_error(f"Error during trading for {asset_name}: {str(e)}")
                        continue

                await asyncio.sleep(10)

        except Exception as e:
            log_error(f"Critical error in trading loop: {str(e)}")
            raise

    def stop(self):
        self.trade_started = False

    def calculate_ma(self, df, period=20):
        df[f'ma_{period}'] = df['close'].rolling(window=period).mean()
        return df

    def generate_ma_signal(self, df):
        if df['close'].iloc[-1] > df[f'ma_20'].iloc[-1]:
            return 'long'
        elif df['close'].iloc[-1] < df[f'ma_20'].iloc[-1]:
            return 'short'
        return 'hold'

    def calculate_stochastic(self, df, period=14, k_period=3, d_period=3):
        low_min = df['low'].rolling(window=period).min()
        high_max = df['high'].rolling(window=period).max()
        df['%K'] = 100 * (df['close'] - low_min) / (high_max - low_min)
        df['%D'] = df['%K'].rolling(window=d_period).mean()
        return df

    def generate_stochastic_signal(self, df):
        if df['%K'].iloc[-1] > df['%D'].iloc[-1] and df['%K'].iloc[-2] <= df['%D'].iloc[-2]:
            return 'long'
        elif df['%K'].iloc[-1] < df['%D'].iloc[-1] and df['%K'].iloc[-2] >= df['%D'].iloc[-2]:
            return 'short'
        return 'hold'

    def calculate_macd(self, df, fast_period=12, slow_period=26, signal_period=9):
        df['ema_fast'] = df['close'].ewm(span=fast_period, adjust=False).mean()
        df['ema_slow'] = df['close'].ewm(span=slow_period, adjust=False).mean()
        df['macd'] = df['ema_fast'] - df['ema_slow']
        df['macd_signal'] = df['macd'].ewm(span=signal_period, adjust=False).mean()
        return df

    def generate_macd_signal(self, df):
        if df['macd'].iloc[-1] > df['macd_signal'].iloc[-1] and df['macd'].iloc[-2] <= df['macd_signal'].iloc[-2]:
            return 'long'
        elif df['macd'].iloc[-1] < df['macd_signal'].iloc[-1] and df['macd'].iloc[-2] >= df['macd_signal'].iloc[-2]:
            return 'short'
        return 'hold'
    def calculate_atr(self, df, period=14):
    # Shift the close price to calculate the difference for the previous period
        df['previous_close'] = df['close'].shift(1)
        
        # Calculate True Range (TR)
        df['tr'] = df.apply(
            lambda row: max(
                row['high'] - row['low'], 
                abs(row['high'] - row['previous_close']), 
                abs(row['low'] - row['previous_close'])
            ), axis=1
        )
        
        # Calculate Average True Range (ATR)
        df['atr'] = df['tr'].rolling(window=period).mean()
        return df


    def generate_atr_signal(self, df, threshold=2):
        if df['atr'].iloc[-1] > threshold:
            return 'long'
        elif df['atr'].iloc[-1] < threshold:
            return 'short'
        return 'hold'

    # VWAP Calculation
    def calculate_vwap(self, df):
        df['vwap'] = (df['volume'] * (df['high'] + df['low'] + df['close']) / 3).cumsum() / df['volume'].cumsum()
        return df

    def generate_vwap_signal(self, df):
        if df['close'].iloc[-1] > df['vwap'].iloc[-1]:
            return 'long'
        elif df['close'].iloc[-1] < df['vwap'].iloc[-1]:
            return 'short'
        return 'hold'

    # Fibonacci Retracement Levels
    def calculate_fibonacci(self, df):
        max_price = df['high'].max()
        min_price = df['low'].min()
        diff = max_price - min_price
        levels = {
            'level_0': max_price,
            'level_1': max_price - 0.236 * diff,
            'level_2': max_price - 0.382 * diff,
            'level_3': max_price - 0.618 * diff,
            'level_4': min_price
        }
        return levels

    def generate_fibonacci_signal(self, df, levels):
        last_close = df['close'].iloc[-1]
        if last_close <= levels['level_1']:
            return 'long'
        elif last_close >= levels['level_3']:
            return 'short'
        return 'hold'

    # RSI Calculation
    def calculate_rsi(self, df, period=14):
        delta = df['close'].diff()
        gain = delta.where(delta > 0, 0)
        loss = -delta.where(delta < 0, 0)
        avg_gain = gain.rolling(window=period).mean()
        avg_loss = loss.rolling(window=period).mean()
        rs = avg_gain / avg_loss
        df['rsi'] = 100 - (100 / (1 + rs))
        return df

    def generate_rsi_signal(self, df, overbought=70, oversold=30):
        last_rsi = df['rsi'].iloc[-1]
        if last_rsi > overbought:
            return 'short'
        elif last_rsi < oversold:
            return 'long'
        return 'hold'

    # Bollinger Bands Calculation
    def calculate_bollinger_bands(self, df, period=20, std_dev=2):
        df['middle_band'] = df['close'].rolling(window=period).mean()
        df['std_dev'] = df['close'].rolling(window=period).std()
        df['upper_band'] = df['middle_band'] + (df['std_dev'] * std_dev)
        df['lower_band'] = df['middle_band'] - (df['std_dev'] * std_dev)
        return df

    def generate_bollinger_signal(self, df):
        last_close = df['close'].iloc[-1]
        if last_close > df['upper_band'].iloc[-1]:
            return 'short'
        elif last_close < df['lower_band'].iloc[-1]:
            return 'long'
        return 'hold'
