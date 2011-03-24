/*
 * Copyright (C) 2006-2011 Julien Ridoux <julien@synclab.org>
 *
 * This file is part of the radclock program.
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */



#include <Python.h>
#include "structmember.h"

#include <radclock.h>



/* 
 * Create an python object for the radclock instance 
 * It contains a single member that is a reference to the C instance of the 
 * RADclock. We don't allow to modify the member directly (letting users play
 * with pointers from Python is a bad idea, right?). So no getter and setters
 * on that member but methods to access the C radclock structure members.
 */
typedef struct {
	PyObject_HEAD
	PyObject *radclock;
} pyradclock;



/* 
 * Destructor, Constructor, Initialiser
 *
 * XXX: I am not too confident with the management of references from Python
 * to C and the other way around. Is there an expert around who could check that?
 */

static void
pyradclock_destroy ( pyradclock* self )
{
	Py_XDECREF(self->radclock);
	radclock_destroy((struct radclock *) self->radclock);
	self->ob_type->tp_free((PyObject*) self);
}


static PyObject *
pyradclock_create ( PyTypeObject *type, PyObject *args, PyObject *kwds )
{
	pyradclock *self;
	int ret;

	self = (pyradclock*) type->tp_alloc(type, 0);
	if (self != NULL) 
	{
		self->radclock = (PyObject *) radclock_create();
		if (self->radclock == NULL) 
		{
			PyErr_SetString(PyExc_Exception, "Creation of RADclock instance failed");
			Py_DECREF(self);
			return NULL;
		}
		ret = radclock_init((struct radclock *) self->radclock);
		if ( ret < 0 )
		{
			PyErr_SetString(PyExc_Exception, "Initialisation of RADclock instance failed.");	
			pyradclock_destroy( self );
			return NULL;
		}
	}

	return (PyObject *) self;
}


static int
pyradclock_init( pyradclock *self, PyObject *args, PyObject *kwds )
{
	/* Init has been called when creating the object. Don't want to open
	 * multiple IPC sockets for nothing. Let's not confuse things
	 */ 
	return 0;
}


/*
 * Object members
 * 
 * We do not give direct access to the radclock handle (of courser)
 * So no mention of it in the member list
 */
static PyMemberDef pyradclock_members[] = {
	{NULL} /* Sentinel to keep last */
};


/*
 * Geters and Seters
 *
 * As before, no need to get (or set!) the radclock handle
 */
static PyGetSetDef pyradclock_getseters[] = {
	{NULL} /* Sentinel to keep last */
};



/*
 *  Object methods
 *  
 *  Most of the C radclock API functions that take a radclock
 *  handle as a parameter should be listed in here
 */

/* TODO: Wrappers for methods from the API to implement + packet capture */
// int radclock_set_autoupdate(struct radclock *handle, radclock_autoupdate_t *update_mode);
// int radclock_get_autoupdate(struct radclock *handle, radclock_autoupdate_t *update_mode);
// int radclock_gettimeofday(struct radclock *handle, struct timeval *abstime_tv);
// int radclock_set_local_period_mode(struct radclock *handle, radclock_local_period_t *local_period_mode);
// int radclock_get_local_period_mode(struct radclock *handle, radclock_local_period_t *local_period_mode);
// int radclock_vcount_to_abstime(struct radclock *handle, const vcounter_t *tsc, struct timeval *abstime_tv);
// int radclock_vcount_to_abstime_fp(struct radclock *handle, const vcounter_t *tsc, long double *abstime_fp);
// int radclock_elapsed(struct radclock *handle, const vcounter_t *from_tsc, struct timeval *duration_tv);
// int radclock_elapsed_fp(struct radclock *handle, const vcounter_t *from_tsc, long double *duration_fp);
// int radclock_duration(struct radclock *handle, const vcounter_t *from_tsc, const vcounter_t *till_tsc, struct timeval *duration_tv);
// int radclock_duration_fp(struct radclock *handle, const vcounter_t *from, const vcounter_t *till, long double *duration_fp);
// 


// XXX TODO XXX: implemented wrappers as returning function instead of filling variables by reference
// that may have to change in the future, no? Not done because I have a doubt on how to handle
// reference count here and I am afraid of memory leaks ...
static PyObject *
pyradclock_get_vcounter ( pyradclock *self )
{
	int ret;
	vcounter_t vcount;
	ret = radclock_get_vcounter((struct radclock *) (self->radclock), &vcount);
	if ( ret != 0 )
		vcount = 0;
	return PyLong_FromUnsignedLongLong(vcount);
}


static PyObject *
pyradclock_gettimeofday_fp ( pyradclock *self )
{
	int ret;
	long double time;
	ret = radclock_gettimeofday_fp((struct radclock *) (self->radclock), &time);
	if ( ret != 0 )
		time = -1.0;
	return PyFloat_FromDouble(time);
}


static PyObject *
pyradclock_get_clockerror_bound( pyradclock *self )
{
	int ret;
	double error_bound;
	ret = radclock_get_clockerror_bound((struct radclock *) (self->radclock), &error_bound);
	if ( ret != 0 )
		error_bound = -1.0;
	return PyFloat_FromDouble(error_bound);
}


static PyObject *
pyradclock_get_clockerror_bound_avg( pyradclock *self )
{
	int ret;
	double error_bound_avg;
	ret = radclock_get_clockerror_bound_avg((struct radclock *) (self->radclock), &error_bound_avg);
	if ( ret != 0 )
		error_bound_avg = -1.0;
	return PyFloat_FromDouble(error_bound_avg);
}


static PyObject *
pyradclock_get_clockerror_bound_std( pyradclock *self )
{
	int ret;
	double error_bound_std;
	ret = radclock_get_clockerror_bound_std((struct radclock *) (self->radclock), &error_bound_std);
	if ( ret != 0 )
		error_bound_std = -1.0;
	return PyFloat_FromDouble(error_bound_std);
}


static PyObject *
pyradclock_get_min_RTT( pyradclock *self )
{
	int ret;
	double min_RTT;
	ret = radclock_get_min_RTT((struct radclock *) (self->radclock), &min_RTT);
	if ( ret != 0 )
		min_RTT = -1.0;
	return PyFloat_FromDouble(min_RTT);
}


static PyObject *
pyradclock_get_last_stamp ( pyradclock *self )
{
	int ret;
	vcounter_t last_tsc;
	ret = radclock_get_last_stamp((struct radclock *) (self->radclock), &last_tsc);
	if ( ret != 0 )
		last_tsc = 0;
	return PyLong_FromUnsignedLongLong(last_tsc);
}


static PyObject *
pyradclock_get_till_stamp ( pyradclock *self )
{
	int ret;
	vcounter_t till_tsc;
	ret = radclock_get_till_stamp((struct radclock *) (self->radclock), &till_tsc);
	if ( ret != 0 )
		till_tsc = 0;
	return PyLong_FromUnsignedLongLong(till_tsc);
}


static PyObject *
pyradclock_get_period ( pyradclock *self )
{
	int ret;
	double period;
	ret = radclock_get_period((struct radclock *) (self->radclock), &period);
	if ( ret != 0 )
		period = -1.0;
	return PyFloat_FromDouble(period);
}


static PyObject *
pyradclock_get_offset ( pyradclock *self )
{
	int ret;
	long double offset;
	ret = radclock_get_offset((struct radclock *) (self->radclock), &offset);
	if ( ret != 0 )
		offset = -1.0;
	return PyFloat_FromDouble(offset);
}


static PyObject *
pyradclock_get_period_error ( pyradclock *self )
{
	int ret;
	double period_error;
	ret = radclock_get_period_error((struct radclock *) (self->radclock), &period_error);
	if ( ret != 0 )
		period_error = -1.0;
	return PyFloat_FromDouble(period_error);
}


static PyObject *
pyradclock_get_offset_error ( pyradclock *self )
{
	int ret;
	double offset_error;
	ret = radclock_get_offset_error((struct radclock *) (self->radclock), &offset_error);
	if ( ret != 0 )
		offset_error = -1.0;
	return PyFloat_FromDouble(offset_error);
}

static PyObject *
pyradclock_get_status ( pyradclock *self )
{
	int ret;
	unsigned int status;
	ret = radclock_get_status((struct radclock *) (self->radclock), &status);
	if ( ret != 0 )
		status = 0;
	/* Need Python >= 2.4 */
	return Py_BuildValue("l", status);
}



/*
 * List of all implemented object methods
 */
static PyMethodDef pyradclock_methods[] = {
//	{ "gettimeofday_fp", pyradclock_gettimeofday_fp, METH_VARARGS, "Get the time from the RADclock." },
	{ "get_vcounter", 		(PyCFunction) pyradclock_get_vcounter, 		METH_NOARGS, "Get the current vcounter value." },
	{ "gettimeofday_fp", 	(PyCFunction) pyradclock_gettimeofday_fp, 	METH_NOARGS, "Get the time from the RADclock." },
	{ "get_clockerror_bound", 	(PyCFunction) pyradclock_get_clockerror_bound, 	METH_NOARGS, "Get instantaneous estimate of RADclock error." },
	{ "get_clockerror_bound_avg", 	(PyCFunction) pyradclock_get_clockerror_bound_avg, 	METH_NOARGS, "Get average estimate of RADclock error." },
	{ "get_clockerror_bound_std", 	(PyCFunction) pyradclock_get_clockerror_bound_std, 	METH_NOARGS, "Get standard deviation estimate of RADclock error." },
	{ "get_min_RTT", 	(PyCFunction) pyradclock_get_min_RTT, 	METH_NOARGS, "Get estimate of minimum RTT to the reference clock." },
	{ "get_last_stamp", 	(PyCFunction) pyradclock_get_last_stamp, 	METH_NOARGS, "Get the last stamp the RADclock was updated." },
	{ "get_till_stamp", 	(PyCFunction) pyradclock_get_till_stamp, 	METH_NOARGS, "Get the foreseen stamp the RADclock will be updated." },
	{ "get_period", 		(PyCFunction) pyradclock_get_period, 		METH_NOARGS, "Get the estimate of the oscillator period.." },
	{ "get_offset", 		(PyCFunction) pyradclock_get_offset, 		METH_NOARGS, "Get the estimate of the RADclock offset correction." },
	{ "get_period_error", 	(PyCFunction) pyradclock_get_period_error, 	METH_NOARGS, "Get the error on the period estimate.." },
	{ "get_offset_error", 	(PyCFunction) pyradclock_get_offset_error, 	METH_NOARGS, "Get the error on the offset estimate.." },
	{ "get_status", 		(PyCFunction) pyradclock_get_status, 		METH_NOARGS, "Get the RADclock status." },
	{ NULL, NULL, 0, NULL }	/* Sentinel to keep last */
};



/* 
 * Type definition of the radclock object
 */
static PyTypeObject pyradclockType = {
	PyObject_HEAD_INIT(NULL)
	0,											/* ob_size */
	"radclock.radclock",						/* tp_name */
	sizeof(pyradclock),							/* tp_basicsize */
	0,											/* tp_itemsize */
	(destructor)pyradclock_destroy,				/* tp_dealloc */
	0,											/* tp_print */
	0,											/* tp_getattr */
	0,											/* tp_setattr */
	0,											/* tp_compare */
	0,											/* tp_repr */
	0,											/* tp_as_number */
	0,											/* tp_as_sequence */
	0,											/* tp_as_mapping */
	0,											/* tp_hash */
	0,											/* tp_call */
	0,											/* tp_str */
	0,											/* tp_getattro */
	0,											/* tp_setattro */
	0,											/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,		/* tp_flags */
	"radclock objects",							/* tp_doc */
	0,											/* tp_traverse */
	0,											/* tp_clear */
	0,											/* tp_richcompare */
	0,											/* tp_weaklistoffset */
	0,											/* tp_iter */
	0,											/* tp_iternext */
	pyradclock_methods,							/* tp_methods */
	pyradclock_members,							/* tp_members */
	pyradclock_getseters,						/* tp_getset */
	0,											/* tp_base */
	0,											/* tp_dict */
	0,											/* tp_descr_get */
	0,											/* tp_descr_set */
	0,											/* tp_dictoffset */
	(initproc)pyradclock_init,					/* tp_init */
	0,											/* tp_alloc */
	pyradclock_create,							/* tp_new */
};






/*
 * Module methods
 *
 * The ones that are not directly related to the radclock handle
 */
// TODO ... keep for historical calls
static PyObject *
pyradclock_readtsc ( PyObject *self, PyObject *args )
{
	return PyLong_FromUnsignedLongLong(radclock_readtsc());
}


/* 
 * Module's Method Table
 */
static PyMethodDef radclock_module_methods[] = {
	{ "readtsc", pyradclock_readtsc, METH_VARARGS, "Read the RAD value on the CPU." },
	{ NULL, NULL, 0, NULL }	/* Sentinel to keep last */
};



/*
 * Init Function
 */
#ifndef PyMODINIT_FUNC 	/* Declaration for DLL import / export */
#define PyMODINIT_FUNC void
#endif

PyMODINIT_FUNC
initradclock(void)
{
	PyObject *m;

	/* In place of tp_alloc */
	if ( PyType_Ready(&pyradclockType) < 0 )
		return;

	m =  Py_InitModule3("radclock", radclock_module_methods, "Module to access RADclock time.");

	if ( m == NULL )
		return;

	Py_INCREF(&pyradclockType);

	PyModule_AddObject(m, "radclock", (PyObject *) &pyradclockType); 
}


