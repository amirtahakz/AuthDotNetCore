using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;
using Ui.Data.Context;
using Ui.Data.Entities;

namespace Ui.Core.Services
{
    public abstract class BaseService<TEntity> where TEntity : BaseEntity
    {
        #region Connections

        private ApplicationDbContext _context;
        private DbSet<TEntity> _dbset;
        protected BaseService(ApplicationDbContext context)
        {
            _context = context;
            _dbset = context.Set<TEntity>();
        }

        #endregion

        #region GetAll

        public virtual async Task<IEnumerable<TEntity>> GetAllAsync(Expression<Func<TEntity, bool>> where = null, Func<IQueryable<TEntity>, IOrderedQueryable<TEntity>> orderby = null, string includes = "")
        {
            IQueryable<TEntity> query = _dbset;
            if (where != null)
            {
                query = query.Where(where);
            }
            if (orderby != null)
            {
                query = orderby(query);
            }
            if (includes != "")
            {
                foreach (var item in includes.Split(','))
                {
                    query = query.Include(includes);
                }
            }
            return await query.Where(x => x.IsRemove == false).ToListAsync();

        }
        public virtual IQueryable<TEntity> Table()
        {
            return _dbset.AsNoTracking();
        }
        public virtual IQueryable<TEntity> TableTracking()
        {
            return _dbset;
        }

        #endregion

        #region GetById|GetByIdAsync

        public virtual TEntity GetById(Guid id)
        {
            if (!_dbset.Any(i => i.Id == id))
            {
                throw new Exception("The ID you are looking for is not exist");
            }
            var model = _dbset.Find(id);
            if (model.IsRemove == true)
            {
                throw new Exception("Your ID is not available in the system");
            }
            return model;
        }
        public virtual async Task<TEntity> GetByIdAsync(Guid id)
        {
            if (!_dbset.Any(i => i.Id == id))
            {
                throw new Exception("The ID you are looking for is not exist");
            }
            var model = await _dbset.FindAsync(id);
            if (model.IsRemove == true)
            {
                throw new Exception("Your ID is not available in the system");
            }
            return model;
        }

        #endregion

        #region Add|Update|Delete|Remove

        public virtual async Task<TEntity> AddAsync(TEntity entity)
        {
            try
            {
                entity.IsRemove = false;
                var res = await _dbset.AddAsync(entity);
                await _context.SaveChangesAsync();
                return res.Entity;
            }
            catch
            {

                throw new Exception("There was a problem Adding");
            }
        }
        public virtual async Task AddAsync(IEnumerable<TEntity> entities)
        {
            try
            {
                foreach (var entity in entities)
                {
                    entity.IsRemove = false;
                }
                await _dbset.AddRangeAsync(entities);
                await _context.SaveChangesAsync();
            }
            catch
            {

                throw new Exception("There was a problem Adding");
            }
        }
        public virtual async Task<TEntity> UpdateAsync(TEntity entity)
        {
            try
            {
                var res = _dbset.Attach(entity);
                entity.IsRemove = false;
                _context.Entry(entity).State = EntityState.Modified;
                await _context.SaveChangesAsync();
                return res.Entity;
            }
            catch
            {

                throw new Exception("There was a problem changing");
            }

        }
        public virtual async Task<bool> UpdateAsync(IEnumerable<TEntity> entities)
        {
            try
            {
                _dbset.AttachRange(entities);
                foreach (var entity in entities)
                {
                    entity.IsRemove = false;
                    _context.Entry(entity).State = EntityState.Modified;
                    await _context.SaveChangesAsync();
                }
                return true;
            }
            catch
            {

                throw new Exception("There was a problem changing");
            }

        }
        public virtual async Task<bool> DeleteAsync(TEntity entity)
        {
            try
            {
                if (_context.Entry(entity).State == EntityState.Detached)
                {
                    _dbset.Attach(entity);
                }
                _dbset.Remove(entity);
                await _context.SaveChangesAsync();
                return true;
            }
            catch
            {

                throw new Exception("There was a problem Deleting");
            }

        }
        public virtual async Task<bool> DeleteAsync(IEnumerable<TEntity> entities)
        {
            try
            {
                if (entities?.Any() != true)
                {
                    throw new ArgumentException(nameof(entities));
                }
                _dbset.RemoveRange(entities);
                await _context.SaveChangesAsync();
                return true;
            }
            catch
            {

                throw new Exception("There was a problem Deleting");
            }

        }
        public virtual async Task<bool> DeleteAsync(Guid id)
        {
            try
            {
                var entity = GetById(id);
                _dbset.Remove(entity);
                await _context.SaveChangesAsync();
                return true;
            }
            catch
            {

                throw new Exception("There was a problem Deleting");
            }

        }
        public virtual async Task<bool> RemoveAsync(TEntity entity)
        {
            try
            {
                if (_context.Entry(entity).State == EntityState.Detached)
                {
                    _dbset.Attach(entity);
                }
                var model = GetById(entity.Id);
                model.IsRemove = true;
                await _context.SaveChangesAsync();
                return true;
            }
            catch
            {

                throw new Exception("There was a problem Removing");
            }

        }
        public virtual async Task<bool> RemoveAsync(Guid id)
        {
            try
            {
                var model = GetById(id);
                model.IsRemove = true;
                await _context.SaveChangesAsync();
                return true;
            }
            catch
            {

                throw new Exception("There was a problem Removing");
            }
        }

        #endregion

    }
}
