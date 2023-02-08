using Microsoft.Win32;
using ProjectScan.Services;
using System;
using System.Collections.Generic;
using System.IO;
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
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace ProjectScan
{
    /// <summary>
    /// The application's current screen state.
    /// This represents the control flow of the system.
    /// </summary>
    public enum ApplicationScreenState
    {
        /// <summary>
        /// The system is in an undefined / invalid state.
        /// </summary>
        Unknown=0x0,
        /// <summary>
        /// The user is selecting a file.
        /// </summary>
        SelectFile=0x1,
        /// <summary>
        /// The scan is in progress. Analysis is being conducted.
        /// </summary>
        ScanningInProgress=0x2,
        /// <summary>
        /// The scan is complete. Results are being shown to the user.
        /// </summary>
        ScanComplete=0x3,
        /// <summary>
        /// A fatal error occurred, from which we cannot recover.
        /// </summary>
        FatalError=0x4
    }


    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        //Clock? tick { get; set; } = null;

        /// <summary>
        /// The default colour of a button as it is rendered at runtime.
        /// We store this to reset the button's colour in the case that an error is resolved.
        /// </summary>
        private Brush ButtonDefaultColour { get; set; }

        private readonly static Brush BgDanger = Brushes.Red;

        private ApplicationScreenState state { get; set; } = ApplicationScreenState.SelectFile;

        private static IViralTelemetryService Scanner { get; set; } = new ViralTelemetryService();

        // Filepath of the file chosen by the user to be scanned.
        private string filepath;

        public MainWindow()
        {
            InitializeComponent();
            ButtonDefaultColour = FilePicker.Background;
            using (var ctx = new MalwareScannerContext())
            {
                if(ctx.KnownBadHashes.Count() <= 0)
                {
                    FatalException("Database contains no hashes.", FaultCode.DatabaseError);
                }
                //TODO: CRC / self integrity checks of database.
            }
            //tick = new(ClockView, this);
        }

        public enum FaultCode
        {
            None=0x0,
            DatabaseError=0x1
        }

        public void FatalException(string reason, FaultCode code)
        {
            ErrorString.Text = $"An error has occurred: {reason} (error code {(int)code})";
            SetApplicationScreen(ApplicationScreenState.FatalError);

        }

        /// <summary>
        /// Handle changing the application screen.
        /// This will selectively show / occlude relevent elements.
        /// </summary>
        /// <param name="_state">The new state / screen to show.</param>
        public void SetApplicationScreen(ApplicationScreenState _state)
        {
            this.state = _state;
            switch (state)
            {
                case (ApplicationScreenState.FatalError):
                    ErrorDisplay.Visibility = Visibility.Visible;
                    SelectFile.Visibility = Visibility.Hidden;
                    ScanningInProgress.Visibility = Visibility.Hidden;
                    ScanComplete.Visibility = Visibility.Hidden;
                    break;

                case (ApplicationScreenState.SelectFile):
                    SelectFile.Visibility = Visibility.Visible;
                    ScanningInProgress.Visibility = Visibility.Hidden;
                    ScanComplete.Visibility = Visibility.Hidden;
                    break;
                case (ApplicationScreenState.ScanningInProgress):
                    SelectFile.Visibility = Visibility.Hidden;
                    ScanningInProgress.Visibility = Visibility.Visible;
                    ScanComplete.Visibility = Visibility.Hidden;
                    break;
                case (ApplicationScreenState.ScanComplete):
                    SelectFile.Visibility = Visibility.Hidden;
                    ScanningInProgress.Visibility = Visibility.Hidden;
                    ScanComplete.Visibility = Visibility.Visible;
                    //Fill out the results...
                    Diagnosis.Text = ScanningResult.Categorisation.ToString();
                    Confidence.Text = $"Confidence: {ScanningResult.Confidence}";
                    break;
            }
        }

        List<IViralTelemetryService> DetectionEngines = new List<IViralTelemetryService>()
        {
            new SHA256HashTelemetryService()
        };
        public ViralTelemetryResult ScanningResult { get; set; }

        private void Scan()
        {
            if (filepath == null || filepath.Length <= 0)
            {
                throw new InvalidOperationException();
            }
            foreach (IViralTelemetryService detectionEngine in DetectionEngines)
            {
                ScanningResult = detectionEngine.Scan(filepath, out ViralTelemetryErrorFlags flags);
                if (ScanningResult.Categorisation != ViralTelemetryCategorisation.Negative)
                {
                    throw new NotImplementedException();
                }
            }
            SetApplicationScreen(ApplicationScreenState.ScanComplete);
        }

        /// <summary>
        /// Allow the user to select a file for analysis.
        /// The user is presented with a standard windows file-input dialogue.
        /// From there, assuming the user confirmed their choice with the win-native file picker, the program will
        /// begin scanning.
        /// TODO: Implement scanning.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ChooseFile(object sender, RoutedEventArgs e)
        {
            //Show the user a win-native file picker. This is rendered by the OS.
            bool err = false;
            try
            {

                OpenFileDialog picker = new();


                if (picker.ShowDialog() == true)
                {
                    //User confirmed file choice and did not cancel.
                    // Set field that stores the scanned file's filepath.
                    this.filepath = picker.FileName;
                    //Safety check: Attempt to locate the file on the system.
                    //It is possible that the file was deleted after the user opened the file dialogue.
                    if (!System.IO.File.Exists(this.filepath))
                    {
                        throw new FileNotFoundException();
                    }
#if DEBUG
                    Console.WriteLine(this.filepath);
#endif

                    SetApplicationScreen(ApplicationScreenState.ScanningInProgress);
                    ScanningText.Text = picker.SafeFileName + " is being scanned..."; // TODO: get filename from MainWindow.
                    //TODO: Perform scanning logic here.
                    Scan();
                }
            }
            catch (FileNotFoundException)
            {
                FilePicker.Content = "File not found.";
                err = true;
            }
            finally
            {
                if (err)
                {
                    FilePicker.Background = BgDanger;
                }
                else
                {
                    FilePicker.Background = ButtonDefaultColour;
                }
            }
        }

        /// <summary>
        /// Drag drop handler.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void FilePicker_Drop(object sender, DragEventArgs e)
        {
            //Is the user trying to pass us a file?
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                bool err = false;
                //More than one file is possible. TODO: Handle this?
                try
                {
                    //All the files that the user has tried to drop in.
                    string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                    string target = files[0];
                    //Safety check: Attempt to locate the file on the system.
                    //It is possible that the file was deleted after the user opened the file dialogue.
                    if (!System.IO.File.Exists(target))
                    {
                        throw new FileNotFoundException();
                    }
#if DEBUG
                    Console.WriteLine(target);

#endif
                    
                    // Set field that stores the filepath for later usage.
                    this.filepath = target;
                    SetApplicationScreen(ApplicationScreenState.ScanningInProgress);
                    //TODO: Perform scanning logic here.

                }
                catch (FileNotFoundException)
                {
                    FilePicker.Content = "File not found.";
                    err = true;
                }
                finally
                {
                    if (err)
                    {
                        FilePicker.Background = BgDanger;
                    }
                    else
                    {
                        FilePicker.Background = ButtonDefaultColour;
                    }
                }               
            }
        }

        /// <summary>
        /// Suppress drop-over events to allow for file drag drop.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void FilePicker_PreviewDragOver(object sender, DragEventArgs e)
        {
            e.Handled = true;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void DeleteFile(object sender, RoutedEventArgs e)
        {
            try
            {
                // Throw error if file no longer at specified filepath.
                if (!System.IO.File.Exists(this.filepath))
                {
                    throw new FileNotFoundException();
                }

                //Delete the scanned file.
                System.IO.File.Delete(this.filepath);
            }
            catch
            {
                MessageBox.Show("This file can no longer be found.");
            }

        }

        /// <summary>
        /// Reset the application to the initial state.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ReturnToStart(object sender, RoutedEventArgs e)
        {
            //Reset screen to initial file selection state
            SetApplicationScreen(ApplicationScreenState.SelectFile);
        }
    }
}
