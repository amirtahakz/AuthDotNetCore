using System;
using System.Globalization;


namespace Ui.Core.Utilities
{
    public static class PersianDate
    {
        #region Methods

        public static string ConvertToShamsi(this DateTime value)
        {
            PersianCalendar persiancal = new PersianCalendar();
            return persiancal.GetYear(value) + "/" + persiancal.GetMonth(value).ToString("00") + "/" +
                  persiancal.GetDayOfMonth(value).ToString("00");
        }

        #endregion

    }
}
