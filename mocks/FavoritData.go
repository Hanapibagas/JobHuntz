// Code generated by mockery v2.41.0. DO NOT EDIT.

package mocks

import (
	favorit "JobHuntz/features/favorit"

	mock "github.com/stretchr/testify/mock"

	sql "database/sql"
)

// FavoritData is an autogenerated mock type for the FavDataInterface type
type FavoritData struct {
	mock.Mock
}

// CreateFavorit provides a mock function with given fields: input
func (_m *FavoritData) CreateFavorit(input favorit.Core) (uint, error) {
	ret := _m.Called(input)

	if len(ret) == 0 {
		panic("no return value specified for CreateFavorit")
	}

	var r0 uint
	var r1 error
	if rf, ok := ret.Get(0).(func(favorit.Core) (uint, error)); ok {
		return rf(input)
	}
	if rf, ok := ret.Get(0).(func(favorit.Core) uint); ok {
		r0 = rf(input)
	} else {
		r0 = ret.Get(0).(uint)
	}

	if rf, ok := ret.Get(1).(func(favorit.Core) error); ok {
		r1 = rf(input)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DeleteFavById provides a mock function with given fields: input, id
func (_m *FavoritData) DeleteFavById(input []favorit.Core, id int) error {
	ret := _m.Called(input, id)

	if len(ret) == 0 {
		panic("no return value specified for DeleteFavById")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func([]favorit.Core, int) error); ok {
		r0 = rf(input, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetAllFavorit provides a mock function with given fields: userID
func (_m *FavoritData) GetAllFavorit(userID uint) ([]favorit.Core, error) {
	ret := _m.Called(userID)

	if len(ret) == 0 {
		panic("no return value specified for GetAllFavorit")
	}

	var r0 []favorit.Core
	var r1 error
	if rf, ok := ret.Get(0).(func(uint) ([]favorit.Core, error)); ok {
		return rf(userID)
	}
	if rf, ok := ret.Get(0).(func(uint) []favorit.Core); ok {
		r0 = rf(userID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]favorit.Core)
		}
	}

	if rf, ok := ret.Get(1).(func(uint) error); ok {
		r1 = rf(userID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetDataCompany provides a mock function with given fields: dbRaw, vacancyID
func (_m *FavoritData) GetDataCompany(dbRaw *sql.DB, vacancyID uint) (favorit.DataCompanyCore, error) {
	ret := _m.Called(dbRaw, vacancyID)

	if len(ret) == 0 {
		panic("no return value specified for GetDataCompany")
	}

	var r0 favorit.DataCompanyCore
	var r1 error
	if rf, ok := ret.Get(0).(func(*sql.DB, uint) (favorit.DataCompanyCore, error)); ok {
		return rf(dbRaw, vacancyID)
	}
	if rf, ok := ret.Get(0).(func(*sql.DB, uint) favorit.DataCompanyCore); ok {
		r0 = rf(dbRaw, vacancyID)
	} else {
		r0 = ret.Get(0).(favorit.DataCompanyCore)
	}

	if rf, ok := ret.Get(1).(func(*sql.DB, uint) error); ok {
		r1 = rf(dbRaw, vacancyID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewFavoritData creates a new instance of FavoritData. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewFavoritData(t interface {
	mock.TestingT
	Cleanup(func())
}) *FavoritData {
	mock := &FavoritData{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
