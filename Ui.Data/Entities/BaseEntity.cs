using Microsoft.VisualBasic.CompilerServices;
using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Ui.Data.Entities
{
    public class BaseEntity
    {
        #region Properties

        [Key]
        public Guid Id { get; protected set; }

        [Required(ErrorMessage = "{0} is required.")]
        public DateTime DateCreated { get; set; } = DateTime.Now;

        [DefaultValue(false)]
        [Required(ErrorMessage = "{0} is required.")]
        public bool IsRemove { get; set; }

        #endregion
    }
}
