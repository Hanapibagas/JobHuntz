// Code generated by mockery v2.42.0. DO NOT EDIT.

package mocks

import (
	jobseeker "JobHuntz/features/jobseeker"

	mock "github.com/stretchr/testify/mock"

	multipart "mime/multipart"

	s3manager "github.com/aws/aws-sdk-go/service/s3/s3manager"

	sql "database/sql"

	uploader "github.com/cloudinary/cloudinary-go/v2/api/uploader"
)

// JobseekerData is an autogenerated mock type for the JobseekerDataInterface type
type JobseekerData struct {
	mock.Mock
}

// AddCV provides a mock function with given fields: input
func (_m *JobseekerData) AddCV(input jobseeker.CVCore) error {
	ret := _m.Called(input)

	if len(ret) == 0 {
		panic("no return value specified for AddCV")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(jobseeker.CVCore) error); ok {
		r0 = rf(input)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AddCareer provides a mock function with given fields: input
func (_m *JobseekerData) AddCareer(input jobseeker.CareerCore) error {
	ret := _m.Called(input)

	if len(ret) == 0 {
		panic("no return value specified for AddCareer")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(jobseeker.CareerCore) error); ok {
		r0 = rf(input)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AddEducation provides a mock function with given fields: input
func (_m *JobseekerData) AddEducation(input jobseeker.EducationCore) error {
	ret := _m.Called(input)

	if len(ret) == 0 {
		panic("no return value specified for AddEducation")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(jobseeker.EducationCore) error); ok {
		r0 = rf(input)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AddLicense provides a mock function with given fields: input
func (_m *JobseekerData) AddLicense(input jobseeker.LicenseCore) error {
	ret := _m.Called(input)

	if len(ret) == 0 {
		panic("no return value specified for AddLicense")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(jobseeker.LicenseCore) error); ok {
		r0 = rf(input)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AddSkill provides a mock function with given fields: input
func (_m *JobseekerData) AddSkill(input jobseeker.SkillCore) error {
	ret := _m.Called(input)

	if len(ret) == 0 {
		panic("no return value specified for AddSkill")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(jobseeker.SkillCore) error); ok {
		r0 = rf(input)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AllEmails provides a mock function with given fields: email
func (_m *JobseekerData) AllEmails(email string) (jobseeker.JobseekerCore, error) {
	ret := _m.Called(email)

	if len(ret) == 0 {
		panic("no return value specified for AllEmails")
	}

	var r0 jobseeker.JobseekerCore
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (jobseeker.JobseekerCore, error)); ok {
		return rf(email)
	}
	if rf, ok := ret.Get(0).(func(string) jobseeker.JobseekerCore); ok {
		r0 = rf(email)
	} else {
		r0 = ret.Get(0).(jobseeker.JobseekerCore)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AllUsernames provides a mock function with given fields: username
func (_m *JobseekerData) AllUsernames(username string) (jobseeker.JobseekerCore, error) {
	ret := _m.Called(username)

	if len(ret) == 0 {
		panic("no return value specified for AllUsernames")
	}

	var r0 jobseeker.JobseekerCore
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (jobseeker.JobseekerCore, error)); ok {
		return rf(username)
	}
	if rf, ok := ret.Get(0).(func(string) jobseeker.JobseekerCore); ok {
		r0 = rf(username)
	} else {
		r0 = ret.Get(0).(jobseeker.JobseekerCore)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(username)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CountCV provides a mock function with given fields: dbRaw, seekerID
func (_m *JobseekerData) CountCV(dbRaw *sql.DB, seekerID uint) (uint, error) {
	ret := _m.Called(dbRaw, seekerID)

	if len(ret) == 0 {
		panic("no return value specified for CountCV")
	}

	var r0 uint
	var r1 error
	if rf, ok := ret.Get(0).(func(*sql.DB, uint) (uint, error)); ok {
		return rf(dbRaw, seekerID)
	}
	if rf, ok := ret.Get(0).(func(*sql.DB, uint) uint); ok {
		r0 = rf(dbRaw, seekerID)
	} else {
		r0 = ret.Get(0).(uint)
	}

	if rf, ok := ret.Get(1).(func(*sql.DB, uint) error); ok {
		r1 = rf(dbRaw, seekerID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetByIdJobSeeker provides a mock function with given fields: id
func (_m *JobseekerData) GetByIdJobSeeker(id uint) (*jobseeker.JobseekerCore, error) {
	ret := _m.Called(id)

	if len(ret) == 0 {
		panic("no return value specified for GetByIdJobSeeker")
	}

	var r0 *jobseeker.JobseekerCore
	var r1 error
	if rf, ok := ret.Get(0).(func(uint) (*jobseeker.JobseekerCore, error)); ok {
		return rf(id)
	}
	if rf, ok := ret.Get(0).(func(uint) *jobseeker.JobseekerCore); ok {
		r0 = rf(id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*jobseeker.JobseekerCore)
		}
	}

	if rf, ok := ret.Get(1).(func(uint) error); ok {
		r1 = rf(id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetCareerByID provides a mock function with given fields: career_id
func (_m *JobseekerData) GetCareerByID(career_id uint) (jobseeker.CareerCore, error) {
	ret := _m.Called(career_id)

	if len(ret) == 0 {
		panic("no return value specified for GetCareerByID")
	}

	var r0 jobseeker.CareerCore
	var r1 error
	if rf, ok := ret.Get(0).(func(uint) (jobseeker.CareerCore, error)); ok {
		return rf(career_id)
	}
	if rf, ok := ret.Get(0).(func(uint) jobseeker.CareerCore); ok {
		r0 = rf(career_id)
	} else {
		r0 = ret.Get(0).(jobseeker.CareerCore)
	}

	if rf, ok := ret.Get(1).(func(uint) error); ok {
		r1 = rf(career_id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetCareerList provides a mock function with given fields: seekerID
func (_m *JobseekerData) GetCareerList(seekerID uint) ([]jobseeker.CareerCore, error) {
	ret := _m.Called(seekerID)

	if len(ret) == 0 {
		panic("no return value specified for GetCareerList")
	}

	var r0 []jobseeker.CareerCore
	var r1 error
	if rf, ok := ret.Get(0).(func(uint) ([]jobseeker.CareerCore, error)); ok {
		return rf(seekerID)
	}
	if rf, ok := ret.Get(0).(func(uint) []jobseeker.CareerCore); ok {
		r0 = rf(seekerID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]jobseeker.CareerCore)
		}
	}

	if rf, ok := ret.Get(1).(func(uint) error); ok {
		r1 = rf(seekerID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetEduByID provides a mock function with given fields: eduID
func (_m *JobseekerData) GetEduByID(eduID uint) (jobseeker.EducationCore, error) {
	ret := _m.Called(eduID)

	if len(ret) == 0 {
		panic("no return value specified for GetEduByID")
	}

	var r0 jobseeker.EducationCore
	var r1 error
	if rf, ok := ret.Get(0).(func(uint) (jobseeker.EducationCore, error)); ok {
		return rf(eduID)
	}
	if rf, ok := ret.Get(0).(func(uint) jobseeker.EducationCore); ok {
		r0 = rf(eduID)
	} else {
		r0 = ret.Get(0).(jobseeker.EducationCore)
	}

	if rf, ok := ret.Get(1).(func(uint) error); ok {
		r1 = rf(eduID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetEduList provides a mock function with given fields: seekerID
func (_m *JobseekerData) GetEduList(seekerID uint) ([]jobseeker.EducationCore, error) {
	ret := _m.Called(seekerID)

	if len(ret) == 0 {
		panic("no return value specified for GetEduList")
	}

	var r0 []jobseeker.EducationCore
	var r1 error
	if rf, ok := ret.Get(0).(func(uint) ([]jobseeker.EducationCore, error)); ok {
		return rf(seekerID)
	}
	if rf, ok := ret.Get(0).(func(uint) []jobseeker.EducationCore); ok {
		r0 = rf(seekerID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]jobseeker.EducationCore)
		}
	}

	if rf, ok := ret.Get(1).(func(uint) error); ok {
		r1 = rf(seekerID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetLicenseByID provides a mock function with given fields: licenseID
func (_m *JobseekerData) GetLicenseByID(licenseID uint) (jobseeker.LicenseCore, error) {
	ret := _m.Called(licenseID)

	if len(ret) == 0 {
		panic("no return value specified for GetLicenseByID")
	}

	var r0 jobseeker.LicenseCore
	var r1 error
	if rf, ok := ret.Get(0).(func(uint) (jobseeker.LicenseCore, error)); ok {
		return rf(licenseID)
	}
	if rf, ok := ret.Get(0).(func(uint) jobseeker.LicenseCore); ok {
		r0 = rf(licenseID)
	} else {
		r0 = ret.Get(0).(jobseeker.LicenseCore)
	}

	if rf, ok := ret.Get(1).(func(uint) error); ok {
		r1 = rf(licenseID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetLicenseList provides a mock function with given fields: seekerID
func (_m *JobseekerData) GetLicenseList(seekerID uint) ([]jobseeker.LicenseCore, error) {
	ret := _m.Called(seekerID)

	if len(ret) == 0 {
		panic("no return value specified for GetLicenseList")
	}

	var r0 []jobseeker.LicenseCore
	var r1 error
	if rf, ok := ret.Get(0).(func(uint) ([]jobseeker.LicenseCore, error)); ok {
		return rf(seekerID)
	}
	if rf, ok := ret.Get(0).(func(uint) []jobseeker.LicenseCore); ok {
		r0 = rf(seekerID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]jobseeker.LicenseCore)
		}
	}

	if rf, ok := ret.Get(1).(func(uint) error); ok {
		r1 = rf(seekerID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetSkillByID provides a mock function with given fields: skillID
func (_m *JobseekerData) GetSkillByID(skillID uint) (jobseeker.SkillCore, error) {
	ret := _m.Called(skillID)

	if len(ret) == 0 {
		panic("no return value specified for GetSkillByID")
	}

	var r0 jobseeker.SkillCore
	var r1 error
	if rf, ok := ret.Get(0).(func(uint) (jobseeker.SkillCore, error)); ok {
		return rf(skillID)
	}
	if rf, ok := ret.Get(0).(func(uint) jobseeker.SkillCore); ok {
		r0 = rf(skillID)
	} else {
		r0 = ret.Get(0).(jobseeker.SkillCore)
	}

	if rf, ok := ret.Get(1).(func(uint) error); ok {
		r1 = rf(skillID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetSkillList provides a mock function with given fields: seekerID
func (_m *JobseekerData) GetSkillList(seekerID uint) ([]jobseeker.SkillCore, error) {
	ret := _m.Called(seekerID)

	if len(ret) == 0 {
		panic("no return value specified for GetSkillList")
	}

	var r0 []jobseeker.SkillCore
	var r1 error
	if rf, ok := ret.Get(0).(func(uint) ([]jobseeker.SkillCore, error)); ok {
		return rf(seekerID)
	}
	if rf, ok := ret.Get(0).(func(uint) []jobseeker.SkillCore); ok {
		r0 = rf(seekerID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]jobseeker.SkillCore)
		}
	}

	if rf, ok := ret.Get(1).(func(uint) error); ok {
		r1 = rf(seekerID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetjobseekerByCompany provides a mock function with given fields: input
func (_m *JobseekerData) GetjobseekerByCompany(input uint) (*jobseeker.JobseekerCore, error) {
	ret := _m.Called(input)

	if len(ret) == 0 {
		panic("no return value specified for GetjobseekerByCompany")
	}

	var r0 *jobseeker.JobseekerCore
	var r1 error
	if rf, ok := ret.Get(0).(func(uint) (*jobseeker.JobseekerCore, error)); ok {
		return rf(input)
	}
	if rf, ok := ret.Get(0).(func(uint) *jobseeker.JobseekerCore); ok {
		r0 = rf(input)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*jobseeker.JobseekerCore)
		}
	}

	if rf, ok := ret.Get(1).(func(uint) error); ok {
		r1 = rf(input)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PDF provides a mock function with given fields: input
func (_m *JobseekerData) PDF(input *multipart.FileHeader) (*s3manager.UploadOutput, error) {
	ret := _m.Called(input)

	if len(ret) == 0 {
		panic("no return value specified for PDF")
	}

	var r0 *s3manager.UploadOutput
	var r1 error
	if rf, ok := ret.Get(0).(func(*multipart.FileHeader) (*s3manager.UploadOutput, error)); ok {
		return rf(input)
	}
	if rf, ok := ret.Get(0).(func(*multipart.FileHeader) *s3manager.UploadOutput); ok {
		r0 = rf(input)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*s3manager.UploadOutput)
		}
	}

	if rf, ok := ret.Get(1).(func(*multipart.FileHeader) error); ok {
		r1 = rf(input)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Photo provides a mock function with given fields: input
func (_m *JobseekerData) Photo(input *multipart.FileHeader) (*uploader.UploadResult, error) {
	ret := _m.Called(input)

	if len(ret) == 0 {
		panic("no return value specified for Photo")
	}

	var r0 *uploader.UploadResult
	var r1 error
	if rf, ok := ret.Get(0).(func(*multipart.FileHeader) (*uploader.UploadResult, error)); ok {
		return rf(input)
	}
	if rf, ok := ret.Get(0).(func(*multipart.FileHeader) *uploader.UploadResult); ok {
		r0 = rf(input)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*uploader.UploadResult)
		}
	}

	if rf, ok := ret.Get(1).(func(*multipart.FileHeader) error); ok {
		r1 = rf(input)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ReadCV provides a mock function with given fields: seekerID
func (_m *JobseekerData) ReadCV(seekerID uint) (jobseeker.CVCore, error) {
	ret := _m.Called(seekerID)

	if len(ret) == 0 {
		panic("no return value specified for ReadCV")
	}

	var r0 jobseeker.CVCore
	var r1 error
	if rf, ok := ret.Get(0).(func(uint) (jobseeker.CVCore, error)); ok {
		return rf(seekerID)
	}
	if rf, ok := ret.Get(0).(func(uint) jobseeker.CVCore); ok {
		r0 = rf(seekerID)
	} else {
		r0 = ret.Get(0).(jobseeker.CVCore)
	}

	if rf, ok := ret.Get(1).(func(uint) error); ok {
		r1 = rf(seekerID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Register provides a mock function with given fields: input
func (_m *JobseekerData) Register(input jobseeker.JobseekerRegistCore) error {
	ret := _m.Called(input)

	if len(ret) == 0 {
		panic("no return value specified for Register")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(jobseeker.JobseekerRegistCore) error); ok {
		r0 = rf(input)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveCV provides a mock function with given fields: seekerID
func (_m *JobseekerData) RemoveCV(seekerID uint) error {
	ret := _m.Called(seekerID)

	if len(ret) == 0 {
		panic("no return value specified for RemoveCV")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(uint) error); ok {
		r0 = rf(seekerID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveCareer provides a mock function with given fields: career_id
func (_m *JobseekerData) RemoveCareer(career_id uint) error {
	ret := _m.Called(career_id)

	if len(ret) == 0 {
		panic("no return value specified for RemoveCareer")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(uint) error); ok {
		r0 = rf(career_id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveEducation provides a mock function with given fields: eduID
func (_m *JobseekerData) RemoveEducation(eduID uint) error {
	ret := _m.Called(eduID)

	if len(ret) == 0 {
		panic("no return value specified for RemoveEducation")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(uint) error); ok {
		r0 = rf(eduID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveLicense provides a mock function with given fields: licenseID
func (_m *JobseekerData) RemoveLicense(licenseID uint) error {
	ret := _m.Called(licenseID)

	if len(ret) == 0 {
		panic("no return value specified for RemoveLicense")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(uint) error); ok {
		r0 = rf(licenseID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveSkill provides a mock function with given fields: skillID
func (_m *JobseekerData) RemoveSkill(skillID uint) error {
	ret := _m.Called(skillID)

	if len(ret) == 0 {
		panic("no return value specified for RemoveSkill")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(uint) error); ok {
		r0 = rf(skillID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateCV provides a mock function with given fields: input
func (_m *JobseekerData) UpdateCV(input jobseeker.CVCore) error {
	ret := _m.Called(input)

	if len(ret) == 0 {
		panic("no return value specified for UpdateCV")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(jobseeker.CVCore) error); ok {
		r0 = rf(input)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateCareer provides a mock function with given fields: careerID_int, input
func (_m *JobseekerData) UpdateCareer(careerID_int uint, input jobseeker.CareerCore) error {
	ret := _m.Called(careerID_int, input)

	if len(ret) == 0 {
		panic("no return value specified for UpdateCareer")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(uint, jobseeker.CareerCore) error); ok {
		r0 = rf(careerID_int, input)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateEducation provides a mock function with given fields: eduID, data
func (_m *JobseekerData) UpdateEducation(eduID uint, data jobseeker.EducationCore) error {
	ret := _m.Called(eduID, data)

	if len(ret) == 0 {
		panic("no return value specified for UpdateEducation")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(uint, jobseeker.EducationCore) error); ok {
		r0 = rf(eduID, data)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateLicense provides a mock function with given fields: licenseID, data
func (_m *JobseekerData) UpdateLicense(licenseID uint, data jobseeker.LicenseCore) error {
	ret := _m.Called(licenseID, data)

	if len(ret) == 0 {
		panic("no return value specified for UpdateLicense")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(uint, jobseeker.LicenseCore) error); ok {
		r0 = rf(licenseID, data)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateProfile provides a mock function with given fields: seekerID, data
func (_m *JobseekerData) UpdateProfile(seekerID uint, data jobseeker.JobseekerUpdateCore) error {
	ret := _m.Called(seekerID, data)

	if len(ret) == 0 {
		panic("no return value specified for UpdateProfile")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(uint, jobseeker.JobseekerUpdateCore) error); ok {
		r0 = rf(seekerID, data)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateSkill provides a mock function with given fields: skillID, data
func (_m *JobseekerData) UpdateSkill(skillID uint, data jobseeker.SkillCore) error {
	ret := _m.Called(skillID, data)

	if len(ret) == 0 {
		panic("no return value specified for UpdateSkill")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(uint, jobseeker.SkillCore) error); ok {
		r0 = rf(skillID, data)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewJobseekerData creates a new instance of JobseekerData. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewJobseekerData(t interface {
	mock.TestingT
	Cleanup(func())
}) *JobseekerData {
	mock := &JobseekerData{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}