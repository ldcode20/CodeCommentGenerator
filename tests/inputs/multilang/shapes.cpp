#include <cmath>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace geometry {

class Shape {
public:
    virtual ~Shape() = default;
    virtual double area() const = 0;
    virtual std::string name() const { return "shape"; }
};

class Circle : public Shape {
public:
    explicit Circle(double radius) : radius_(radius) {
        if (radius < 0) {
            throw std::invalid_argument("radius must be non-negative");
        }
    }

    double area() const override { return M_PI * radius_ * radius_; }

private:
    double radius_;
};

template <typename T>
T clamp_value(T value, T low, T high = T(100)) {
    if (value < low) {
        return low;
    }
    return value > high ? high : value;
}

double total_area(const std::vector<std::unique_ptr<Shape>>& shapes) {
    double sum = 0.0;
    for (const auto& shape : shapes) {
        sum += shape->area();
    }
    return sum;
}

}  // namespace geometry
