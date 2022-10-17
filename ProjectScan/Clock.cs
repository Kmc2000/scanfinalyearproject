using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Timers;
using System.Windows.Controls;

namespace ProjectScan
{
    /// <summary>
    /// Utility class to paint a clock component onto the window.
    /// Will update every minute, showing the short time of the host machine.
    /// </summary>
    internal class Clock
    {
        private Timer Tick = new();
        Label? Display { get; set; } = null;
        MainWindow? Window { get; set; } = null;

        /// <summary>
        /// Create a clock.
        /// A reference to a window and clock component are required.
        /// </summary>
        /// <param name="display">The label you wish to paint the time on. This will be updated once per minute.</param>
        /// <param name="window">The window within which the clock resides.</param>
        public Clock(Label display, MainWindow window)
        {
            Tick.Interval = System.TimeSpan.FromMinutes(1).TotalMilliseconds;
            Tick.Elapsed += Tock;
            this.Display = display;
            this.Window = window;
            //Start the clock.
            Tock(null, null);
            Tick.Start();
        }
        /// <summary>
        /// Event fired when the timer ticks (once per minute).
        /// This repaints the clock using the current time of the host machine.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Tock(object? sender, ElapsedEventArgs e)
        {
            if(Display == null || Window == null)
            {
                return;
            }
            Window.Dispatcher.Invoke(() =>
            {
                Display.Content = $"{DateTime.Now.ToShortTimeString()}";
            });
        }
    }
}
