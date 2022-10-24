using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace ProjectScan
{
    /// <summary>
    /// Interaction logic for ScanningInProgress.xaml
    /// </summary>
    public partial class ScanningInProgress : Window
    {
        public ScanningInProgress()
        {
            InitializeComponent();
            ScanningText.Text = "FILENAME is being scanned..."; // TODO: get filename from MainWindow.
        }
    }
}
